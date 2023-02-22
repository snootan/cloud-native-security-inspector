package cspauth

import (
	"context"
	"fmt"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/retry"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"math"
	"sigs.k8s.io/controller-runtime"
	"time"
)

const (
	tokenMaxAgeSeconds   = 600
	providerAccessSecret = "accessSecret"
)

// Provider is an interface to interact with an authorization service
type Provider interface {
	// GetBearerToken retrieves a short-lived access token to use in a single HTTP request
	GetBearerToken(context.Context) (string, error)
}

type cspAuth struct {
	apiToken  string
	cspClient CSPClient

	currentToken string
	expiration   time.Time
}

func (a *cspAuth) GetBearerToken(ctx context.Context) (string, error) {
	if a.currentToken == "" || time.Now().After(a.expiration) {
		if err := a.refreshToken(ctx); err != nil {
			return "", err
		}
	}
	return a.currentToken, nil
}

func (a *cspAuth) refreshToken(ctx context.Context) error {
	return retry.NewRetry(
		retry.WithName("auth token refresh"),
		retry.WithMaxAttempts(3),
		retry.WithIncrementDelay(5*time.Second, 5*time.Second),
	).Run(ctx, func() (bool, error) {
		now := time.Now()
		cspAuthResponse, err := a.cspClient.GetCspAuthorization(ctx, a.apiToken)
		if err != nil {
			fmt.Printf("We got an error back from CSP %s", err)
			return false, nil
		}

		a.currentToken = cspAuthResponse.AccessToken
		expiresIn := time.Duration(math.Min(float64(cspAuthResponse.ExpiresIn), tokenMaxAgeSeconds)) * time.Second
		a.expiration = now.Add(expiresIn)
		fmt.Printf("Obtained CSP access token, next refresh in %s\n", expiresIn)
		return true, nil
	})
}

func NewCSPAuth(ctx context.Context, cspSecretNamespace string, cspSecretName string) (Provider, error) {
	apiToken, err := getCSPTokenFromSecret(ctx, cspSecretNamespace, cspSecretName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CSP api-token: %w", err)
	}
	cspClient, err := NewCspHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("initializing CSP : %w", err)
	}

	provider := &cspAuth{apiToken: apiToken, cspClient: cspClient}
	if err := provider.refreshToken(ctx); err != nil {
		return nil, fmt.Errorf("validating API token validity: %w", err)
	}

	return provider, nil
}

func getCSPTokenFromSecret(ctx context.Context, ns string, secretName string) (string, error) {
	config, err := kubernetes.NewForConfig(controllerruntime.GetConfigOrDie())
	if err != nil {
		log.Error(err, "Failed to get config while fetching secret!")
		return "", err
	}
	secret, err := config.CoreV1().Secrets(ns).Get(ctx, secretName, v1.GetOptions{})
	if err != nil {
		log.Error(err, "Failed to fetch secret")
		return "", err
	}
	cspApiToken := string(secret.Data[providerAccessSecret])
	return cspApiToken, err
}
