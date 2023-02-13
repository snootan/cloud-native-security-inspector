package retry

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultMaxAttempts = 3
	defaultRetryStep   = 3 * time.Second
)

type delayFunc func(attempt int) time.Duration

type retryConfig struct {
	name        string
	maxAttempts int
	delayFunc   delayFunc
}

type Option func(*retryConfig)

// WithName allows configuring the name of the function in the error message
func WithName(name string) Option {
	return func(o *retryConfig) {
		o.name = name
	}
}

// WithMaxAttempts allows configuring the maximum tries for a given function
func WithMaxAttempts(n int) Option {
	return func(o *retryConfig) {
		o.maxAttempts = n
	}
}

// WithCustomDelayFunc allows configuring a custom waiting strategy between retries
func WithCustomDelayFunc(fn delayFunc) Option {
	return func(o *retryConfig) {
		o.delayFunc = fn
	}
}

// WithFixedDelay allows configuring a fixed-delay waiting strategy between retries
func WithFixedDelay(delay time.Duration) Option {
	return func(o *retryConfig) {
		o.delayFunc = func(_ int) time.Duration { return delay }
	}
}

// WithIncrementDelay allows configuring a waiting strategy with a custom base delay and increment
func WithIncrementDelay(baseDuration time.Duration, increment time.Duration) Option {
	return func(o *retryConfig) {
		o.delayFunc = func(n int) time.Duration {
			stepIncrement := increment * time.Duration(n)
			return baseDuration + stepIncrement
		}
	}
}

// WithExponentialBackoff allows configuring an exponential backoff waiting strategy between retries
func WithExponentialBackoff(baseDuration time.Duration, factor float64) Option {
	return func(o *retryConfig) {
		o.delayFunc = func(n int) time.Duration {
			stepMultiplier := math.Pow(factor, float64(n))
			return baseDuration * time.Duration(stepMultiplier)
		}
	}
}

type Retry struct {
	retryConfig
}

func NewRetry(opts ...Option) *Retry {
	var c retryConfig
	for _, o := range append([]Option{
		// Default values
		WithName("retryable function"),
		WithMaxAttempts(defaultMaxAttempts),
		WithFixedDelay(defaultRetryStep),
	}, opts...) {
		o(&c)
	}
	return &Retry{c}
}

func (r *Retry) Run(ctx context.Context, f func() (bool, error)) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	var attempts int
	for {
		if success, err := f(); err != nil {
			return fmt.Errorf("non retryable error running %q: %w", r.name, err)
		} else if success {
			return nil
		} else {
			log.Printf("running %q failed (%d/%d)\n", r.name, attempts+1, r.maxAttempts)
		}

		delay := r.delayFunc(attempts)
		attempts++
		if attempts == r.maxAttempts {
			return fmt.Errorf("giving up retrying, max attempts %d reached", r.maxAttempts)
		}

		timer.Reset(delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// SetNextRetry allows configuring a custom duration only for the next retry calculated
func (r *Retry) SetNextRetry(duration time.Duration) {
	orig := r.delayFunc
	r.delayFunc = func(_ int) time.Duration {
		r.delayFunc = orig // restore original function
		return duration
	}
}

// IsRetriableHTTPStatus checks an http.Response to detect if it should be retried, and when (if specified)
func IsRetriableHTTPStatus(resp *http.Response) (bool, time.Duration) {
	for _, code := range []int{
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusRequestTimeout,
		http.StatusTooManyRequests,
	} {
		if resp.StatusCode == code {
			if retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil {
				return true, time.Duration(retryAfter) * time.Second
			}
			return true, 0
		}
	}
	return false, 0
}
