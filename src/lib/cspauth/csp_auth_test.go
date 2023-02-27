package cspauth

import (
	"context"
	v12 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

func TestNewCSPAuthSuccessCase(t *testing.T) {

	secret := &v12.Secret{}
	secret.Name = "csp-secret"
	secret.Namespace = "csp-namespace"
	secret.Data = map[string][]byte{API_TOKEN: []byte("test-api-token")}

	errorSecret := &v12.Secret{}
	errorSecret.Name = "csp-secret"
	errorSecret.Namespace = "csp-namespace"
	errorSecret.Data = map[string][]byte{API_TOKEN: []byte(SendError)}

	tt := []struct {
		name         string
		secretObject *v12.Secret
		wantErr      bool
	}{
		{
			name:         "Get CSP Auth should Pass",
			secretObject: secret,
			wantErr:      false,
		},
		{
			name:         "Get CSP Auth should fail because no secret found for csp api-token",
			secretObject: nil,
			wantErr:      true,
		},
		{
			name:         "Get CSP Auth should fail with giving up refresh retry(3times)",
			secretObject: errorSecret,
			wantErr:      true,
		},
	}

	for i := range tt {
		tc := tt[i]

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clientSet := fake.NewSimpleClientset()
			if tc.secretObject != nil {
				clientSet = fake.NewSimpleClientset(tc.secretObject)
			}

			tokenManager := NewMockCSPClient()
			provider := &CspAuth{CspClient: tokenManager}
			auth, err := provider.NewCSPAuth(clientSet, context.Background(), secret.Namespace, secret.Name)

			if tc.wantErr && (auth != nil || err == nil) {
				t.Fatal("NewCSPAuth call failed on tc: " + tc.name)
			}

			if !tc.wantErr && (auth == nil || err != nil) {
				t.Fatal("NewCSPAuth call failed on tc: " + tc.name)
			}
		})
	}

}

func TestGetBearerTokenSuccess(t *testing.T) {
	tokenManager := NewMockCSPClient()
	provider := &CspAuth{CspClient: tokenManager}
	authToken, _ := provider.GetBearerToken(context.Background())

	if authToken != DummyAccessToken {
		t.Fatal("GetBearer must not fail in this test case!")
	}
}

func TestGetBearerTokenReturnSameTokenSuccess(t *testing.T) {
	tokenManager := NewMockCSPClient()
	provider := &CspAuth{CspClient: tokenManager}
	authToken, _ := provider.GetBearerToken(context.Background())

	if authToken != DummyAccessToken {
		t.Fatal("GetBearer must not fail in this test case!")
	}

	tokenPrev := DummyAccessToken
	DummyAccessToken = "changed-dummy-access-token"
	authToken1, _ := provider.GetBearerToken(context.Background())

	if authToken != authToken1 {
		t.Fatal("GetBearer must return same token if called consequently, \nAuth1: " + authToken + "\n Auth2: " + authToken1)
	}
	DummyAccessToken = tokenPrev
}
