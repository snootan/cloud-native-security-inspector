package httpauth

import (
	"context"
	"fmt"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/pkg/data/consumers/governor/retry"
	"math"
	"time"

	cspauth "gitlab.eng.vmware.com/csp/go-framework/auth"
)

const tokenMaxAgeSeconds = 600

// Provider is an interface to interact with an authorization service
type Provider interface {
	// GetBearerToken retrieves a short-lived access token to use in a single HTTP request
	GetBearerToken(context.Context) (string, error)
}

type cspAuth struct {
	apiToken     string
	tokenManager cspauth.TokenManager

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
		cspAuthResponse, err := a.tokenManager.GetTokenFromRefreshToken(ctx, a.apiToken)
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

func NewCSPAuth(ctx context.Context, apiToken string) (Provider, error) {
	tokenManager, err := cspauth.InitTokenManagerClient(cspauth.ConsoleDev)
	if err != nil {
		return nil, fmt.Errorf("initializing CSP : %w", err)
	}

	provider := &cspAuth{apiToken: apiToken, tokenManager: tokenManager}
	if err := provider.refreshToken(ctx); err != nil {
		return nil, fmt.Errorf("validating API token validity: %w", err)
	}

	return provider, nil
}
