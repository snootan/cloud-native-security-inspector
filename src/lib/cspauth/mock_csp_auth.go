package cspauth

import (
	"context"
	"errors"
)

// MockProvider is a mock of the Provider interface
type MockProvider struct {
	Token string
}

// NewMockProvider creates a new mock instance
func NewMockProvider() *MockProvider {
	return &MockProvider{}
}

func (m *MockProvider) GetBearerToken(ctx context.Context) (string, error) {
	if m.Token == "" {
		return "", errors.New("No token available!")
	}
	return m.Token, nil
}
