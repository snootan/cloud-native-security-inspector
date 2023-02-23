package cspauth

import (
	"context"
)

// MockProvider is a mock of the Provider interface
type MockProvider struct {
}

// NewMockProvider creates a new mock instance
func NewMockProvider() *MockProvider {
	return &MockProvider{}
}

func (m *MockProvider) GetBearerToken(ctx context.Context) (string, error) {
	return "dummy-token", nil
}
