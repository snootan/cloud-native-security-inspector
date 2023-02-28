package cspauth

import (
	"context"
	"fmt"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/retry"
	v12 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"math"
	"time"
)

const (
	tokenMaxAgeSeconds     = 1700
	apiToken               = "API_TOKEN"
	cspConfigMapName       = "csp-config"
	governorTokenExpiresIn = "governorAccessTokenExpiresIn"
	governorAccessTokenKey = "governorAccessToken"
	Retry                  = 3
)

var RetryDelay time.Duration = 5

// Provider is an interface to interact with an authorization service
type Provider interface {
	// GetBearerToken retrieves a short-lived access token to use in a single HTTP request
	GetBearerToken(kubernetes.Interface, context.Context, string, string) (string, error)
}

type CspAuth struct {
	CspClient CSPClient

	apiToken string
}

func (a *CspAuth) GetBearerToken(clientSet kubernetes.Interface, ctx context.Context, cspSecretNamespace string, cspSecretName string) (string, error) {
	configMap, err := getOrCreateCSPConfigMap(clientSet, ctx, cspSecretNamespace)
	if err != nil {
		return "", err
	}

	accessToken := configMap.Data[governorAccessTokenKey]
	expiresIn, _ := configMap.Data[governorTokenExpiresIn]
	accessTokenExpiresIn, _ := time.Parse(time.Layout, expiresIn)

	if accessToken == "" || time.Now().After(accessTokenExpiresIn) {
		apiToken, err := getCSPTokenFromSecret(clientSet, ctx, cspSecretNamespace, cspSecretName)
		if err != nil {
			return "", fmt.Errorf("Failed to fetch CSP api-token: %w", err)
		}
		a.apiToken = apiToken
		if err := a.refreshToken(ctx, clientSet, cspSecretNamespace, configMap); err != nil {
			return "", err
		}
	}
	return configMap.Data[governorAccessTokenKey], nil
}

func (a *CspAuth) refreshToken(ctx context.Context, clientSet kubernetes.Interface, cspSecretNamespace string, configMap *v12.ConfigMap) error {
	return retry.NewRetry(
		retry.WithName("auth token refresh"),
		retry.WithMaxAttempts(Retry),
		retry.WithIncrementDelay(RetryDelay*time.Second, RetryDelay*time.Second),
	).Run(ctx, func() (bool, error) {
		now := time.Now()
		cspAuthResponse, err := a.CspClient.GetCspAuthorization(ctx, a.apiToken)
		if err != nil {
			log.Error(err, "We got an error back from CSP")
			return false, nil
		}

		expiresIn := time.Duration(math.Min(float64(cspAuthResponse.ExpiresIn), tokenMaxAgeSeconds)) * time.Second
		formattedExpiration := now.Add(expiresIn).Format(time.Layout)

		log.Infof("Refreshed access token for governor: %s which expires in %s", cspAuthResponse.AccessToken, formattedExpiration)
		configMap.Data[governorAccessTokenKey] = cspAuthResponse.AccessToken
		configMap.Data[governorTokenExpiresIn] = formattedExpiration
		_, err = clientSet.CoreV1().ConfigMaps(cspSecretNamespace).Update(ctx, configMap, v1.UpdateOptions{})
		if err != nil {
			log.Error(err, "We got an error updating config map")
			return false, nil
		}
		log.Infof("Obtained CSP access token, next refresh in %s\n", expiresIn)
		return true, nil
	})
}

func getCSPTokenFromSecret(clientSet kubernetes.Interface, ctx context.Context, ns string, secretName string) (string, error) {
	secret, err := clientSet.CoreV1().Secrets(ns).Get(ctx, secretName, v1.GetOptions{})
	if err != nil {
		log.Error(err, "Failed to fetch secret")
		return "", err
	}
	cspApiToken := string(secret.Data[apiToken])
	return cspApiToken, err
}

func getOrCreateCSPConfigMap(clientSet kubernetes.Interface, ctx context.Context, ns string) (*v12.ConfigMap, error) {
	configMap, err := clientSet.CoreV1().ConfigMaps(ns).Get(ctx, cspConfigMapName, v1.GetOptions{})
	if err != nil {
		log.Warning(err, "Failed to fetch configMap, Now Trying to create new.")
		config := &v12.ConfigMap{}
		config.Name = cspConfigMapName
		config.Namespace = ns
		configMap, err = clientSet.CoreV1().ConfigMaps(ns).Create(ctx, config, v1.CreateOptions{})
		if err != nil {
			log.Error(err, "Failed to create configMap.")
			return configMap, err
		}
	}

	if configMap.Data == nil {
		configMap.Data = map[string]string{}
	}
	return configMap, nil

}
