// Package client provides a client of OpenID Connect.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client/logging"
	"github.com/int128/kubelogin/pkg/pkce"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tlsclientconfig/loader"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/oauth2"
)

var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
)

type FactoryInterface interface {
	New(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error)
}

type Factory struct {
	Loader loader.Loader
	Clock  clock.Interface
	Logger logger.Interface
}

func (f *Factory) getClientConfig(config tlsclientconfig.Config) (*tls.Config, error) {
	if config.TlsCertBundle == "" {
		return f.Loader.Load(config)
	} else {

	}
	rawConfig, err := f.Loader.Load(config)

	if err != nil {
		return nil, err
	}

	p12Data, pErr := os.ReadFile(config.TlsCertBundle)
	if pErr != nil {
		fmt.Printf("\n failed to read cert file %v \n", pErr)
		os.Exit(1)
	}

	blocks, cErr := pkcs12.ToPEM(p12Data, config.TlsCertBundlePassword)
	if cErr != nil {
		if strings.Contains(cErr.Error(), "password incorrect") {
			fmt.Println("\nIncorrect p12 file password")
		} else {
			fmt.Printf("\n failed to parse tls file, check file format: %v \n", cErr)
		}
		os.Exit(1)
	}

	tlsCert, tlsErr := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: blocks[0].Bytes,
	}), pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: blocks[3].Bytes,
	}))

	if tlsErr != nil {
		log.Fatalf("error in creating cert pair %v", tlsErr)
		return nil, tlsErr
	}

	intCert, intErr := x509.ParseCertificate(blocks[1].Bytes)
	rootCert, rootErr := x509.ParseCertificate(blocks[2].Bytes)

	if intErr != nil {
		log.Fatalf("error in creating intermediate cert %v", intErr)
		return nil, intErr
	}

	if rootErr != nil {
		log.Fatalf("error in creating root cert %v", rootErr)
		return nil, rootErr
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(intCert)
	caCertPool.AddCert(rootCert)

	// Create a TLS configuration with client certificate and CA certificate
	rawConfig.Certificates = []tls.Certificate{tlsCert}
	rawConfig.RootCAs = caCertPool

	return rawConfig, nil
}

// New returns an instance of infrastructure.Interface with the given configuration.
func (f *Factory) New(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error) {
	rawTLSClientConfig, err := f.getClientConfig(tlsClientConfig)

	if err != nil {
		return nil, fmt.Errorf("could not load the TLS client config: %w", err)
	}
	baseTransport := &http.Transport{
		TLSClientConfig: rawTLSClientConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	loggingTransport := &logging.Transport{
		Base:   baseTransport,
		Logger: f.Logger,
	}
	httpClient := &http.Client{
		Transport: loggingTransport,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	provider, err := gooidc.NewProvider(ctx, prov.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery error: %w", err)
	}
	supportedPKCEMethods, err := extractSupportedPKCEMethods(provider)
	if err != nil {
		return nil, fmt.Errorf("could not determine supported PKCE methods: %w", err)
	}
	deviceAuthorizationEndpoint, err := extractDeviceAuthorizationEndpoint(provider)
	if err != nil {
		return nil, fmt.Errorf("could not determine device authorization endpoint: %w", err)
	}
	return &client{
		httpClient: httpClient,
		provider:   provider,
		oauth2Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     prov.ClientID,
			ClientSecret: prov.ClientSecret,
			Scopes:       append(prov.ExtraScopes, gooidc.ScopeOpenID),
		},
		clock:                       f.Clock,
		logger:                      f.Logger,
		negotiatedPKCEMethod:        determinePKCEMethod(supportedPKCEMethods, prov.PKCEMethod),
		deviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
		useAccessToken:              prov.UseAccessToken,
	}, nil
}

func determinePKCEMethod(supportedMethods []string, preferredMethod oidc.PKCEMethod) pkce.Method {
	switch preferredMethod {
	case oidc.PKCEMethodNo:
		return pkce.NoMethod
	case oidc.PKCEMethodS256:
		return pkce.MethodS256
	default:
		if slices.Contains(supportedMethods, "S256") {
			return pkce.MethodS256
		}
		return pkce.NoMethod
	}
}

func extractSupportedPKCEMethods(provider *gooidc.Provider) ([]string, error) {
	var claims struct {
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&claims); err != nil {
		return nil, fmt.Errorf("invalid discovery document: %w", err)
	}
	return claims.CodeChallengeMethodsSupported, nil
}

func extractDeviceAuthorizationEndpoint(provider *gooidc.Provider) (string, error) {
	var claims struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return "", fmt.Errorf("invalid discovery document: %w", err)
	}
	return claims.DeviceAuthorizationEndpoint, nil
}
