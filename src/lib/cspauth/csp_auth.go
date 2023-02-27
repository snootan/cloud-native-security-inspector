package cspauth

import (
	"context"
	"fmt"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/retry"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"math"
	"time"
)

const (
	tokenMaxAgeSeconds = 600
	API_TOKEN          = "API_TOKEN"
)

// Provider is an interface to interact with an authorization service
type Provider interface {
	// GetBearerToken retrieves a short-lived access token to use in a single HTTP request
	GetBearerToken(context.Context) (string, error)
	NewCSPAuth(kubernetes.Interface, context.Context, string, string) (Provider, error)
}

type CspAuth struct {
	CspClient CSPClient

	apiToken     string
	currentToken string
	expiration   time.Time
}

func (a *CspAuth) GetBearerToken(ctx context.Context) (string, error) {
	if a.currentToken == "" || time.Now().After(a.expiration) {
		if err := a.refreshToken(ctx); err != nil {
			return "", err
		}
	}
	return a.currentToken, nil
}

func (a *CspAuth) refreshToken(ctx context.Context) error {
	return retry.NewRetry(
		retry.WithName("auth token refresh"),
		retry.WithMaxAttempts(3),
		retry.WithIncrementDelay(5*time.Second, 5*time.Second),
	).Run(ctx, func() (bool, error) {
		now := time.Now()
		cspAuthResponse, err := a.CspClient.GetCspAuthorization(ctx, a.apiToken)
		if err != nil {
			log.Error(err, "We got an error back from CSP")
			return false, nil
		}

		a.currentToken = cspAuthResponse.AccessToken
		expiresIn := time.Duration(math.Min(float64(cspAuthResponse.ExpiresIn), tokenMaxAgeSeconds)) * time.Second
		a.expiration = now.Add(expiresIn)
		log.Infof("Obtained CSP access token, next refresh in %s\n", expiresIn)
		return true, nil
	})
}

func (a *CspAuth) NewCSPAuth(clientSet kubernetes.Interface, ctx context.Context, cspSecretNamespace string, cspSecretName string) (Provider, error) {

	apiToken, err := getCSPTokenFromSecret(clientSet, ctx, cspSecretNamespace, cspSecretName)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch CSP api-token: %w", err)
	}
	a.apiToken = apiToken

	if err := a.refreshToken(ctx); err != nil {
		return nil, fmt.Errorf("Validating API token validity: %w", err)
	}

	return a, nil
}

func getCSPTokenFromSecret(clientSet kubernetes.Interface, ctx context.Context, ns string, secretName string) (string, error) {
	secret, err := clientSet.CoreV1().Secrets(ns).Get(ctx, secretName, v1.GetOptions{})
	if err != nil {
		log.Error(err, "Failed to fetch secret")
		return "", err
	}
	cspApiToken := string(secret.Data[API_TOKEN])
	return cspApiToken, err
}
