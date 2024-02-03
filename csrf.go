package csrf

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidToken = errors.New("invalid token")

// TokenProvider responsible for generating and storing unique token
type TokenProvider interface {
	Get(ctx context.Context) (string, error)
	// Check must return error [ErrInvalidToken] if token was not found or expired
	// and must immediately delete the token if found
	Check(ctx context.Context, token string) error
}

type DefaultTokenProvider struct {
	tokens    map[string]int64
	mu        sync.Mutex
	token_ttl time.Duration
}

var _ TokenProvider = (*DefaultTokenProvider)(nil)

func (dtp *DefaultTokenProvider) gc(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	ctx_done := ctx.Done()
	for {
		select {
		case <-ctx_done:
			return
		case <-ticker.C:
		}

		current_time := time.Now()
		dtp.mu.Lock()
		for token, expire_at := range dtp.tokens {
			if !(current_time.Unix() < expire_at) {
				delete(dtp.tokens, token)
			}
		}
		dtp.mu.Unlock()
	}
}

func (dtp *DefaultTokenProvider) Get(_ context.Context) (string, error) {
	uid, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}

	token := uid.String()

	dtp.mu.Lock()
	defer dtp.mu.Unlock()

	dtp.tokens[token] = time.Now().Add(dtp.token_ttl).Unix()

	return token, nil
}

func (dtp *DefaultTokenProvider) Check(_ context.Context, token string) error {
	dtp.mu.Lock()
	defer dtp.mu.Unlock()

	expire_at, found := dtp.tokens[token]
	if !(found && time.Now().Unix() < expire_at) {
		return ErrInvalidToken
	}

	return nil
}

func NewDefaultTokenProvider(ctx context.Context, gc_intrvl time.Duration) *DefaultTokenProvider {
	dtp := &DefaultTokenProvider{tokens: make(map[string]int64)}
	go dtp.gc(ctx, gc_intrvl)
	return dtp
}

type GenerateTokenFunc func() string

type CSRF struct {
	TokenProvider
}

func New(tp TokenProvider) *CSRF {
	return &CSRF{TokenProvider: tp}
}

// GetToken return new token and store it in the [TokenProvider]
func (c *CSRF) GetToken(ctx context.Context) (string, error) {
	return c.TokenProvider.Get(ctx)
}

type (
	TokenSourceFunc        func(*http.Request) string
	csrf_token_context_key int
)

// ContextTokenSource return token from request context or empty string
func ContextTokenSource(r *http.Request) string {
	return r.Context().Value(csrf_token_context_key(0)).(string)
}

// HeaderTokenSource return token from `X-Csrf-Token` header or empty string
func HeaderTokenSource(r *http.Request) string {
	return r.Header.Get("X-Csrf-Token")
}

// FormTokenSource return token from form value
func FormTokenSource(field string) TokenSourceFunc {
	return func(r *http.Request) string {
		return r.FormValue(field)
	}
}

var errInconsistentTokenBetweenSources = errors.New("inconsistent token between sources")

// Validate extract token from the specified sources
// and [ErrInvalidToken] if token is not found or has been expired
func (c *CSRF) Validate(r *http.Request, sources ...TokenSourceFunc) error {
	if len(sources) == 0 {
		panic("`sources` paramter is required")
	}

	token := ""
	for _, source := range sources {
		if token == "" {
			token = source(r)
			continue
		}

		if token != source(r) {
			return errInconsistentTokenBetweenSources
		}
	}

	// shortcut for bad SourceFunc
	if token == "" {
		return ErrInvalidToken
	}

	return c.TokenProvider.Check(r.Context(), token)
}

func (c *CSRF) ValidateMiddleware(handle_err func(http.ResponseWriter, *http.Request, error), sources ...TokenSourceFunc) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handle_err(w, r, c.Validate(r, sources...))
		})
	}
}
