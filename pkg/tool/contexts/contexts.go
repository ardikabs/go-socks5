package contexts

import (
	"context"

	"github.com/ardikabs/socks5/pkg/auth"
	"github.com/go-logr/logr"
)

type connIDKey struct{}
type authKey struct{}
type loggerKey struct{}

func New(ctx context.Context, connID string, logger logr.Logger) context.Context {
	return setCtxWithValues(ctx, connIDKey{}, connID, loggerKey{}, logger)
}

func WithAuth(ctx context.Context, authContext *auth.AuthContext) context.Context {
	return setCtxWithValues(ctx, authKey{}, authContext)
}

func GetAuth(ctx context.Context) *auth.AuthContext {
	val := ctx.Value(authKey{})
	if val == nil {
		return nil
	}

	authContext, ok := val.(*auth.AuthContext)
	if !ok {
		return nil
	}

	return authContext
}

func GetConnID(ctx context.Context) string {
	v := ctx.Value(connIDKey{})
	if v == nil {
		return ""
	}

	reqID, ok := v.(string)
	if !ok {
		return ""
	}

	return reqID
}

func GetLogger(ctx context.Context) logr.Logger {
	v := ctx.Value(loggerKey{})
	if v == nil {
		return logr.Discard()
	}

	log, ok := v.(logr.Logger)
	if !ok {
		return logr.Discard()
	}

	return log
}

func setCtxWithValues(ctx context.Context, keyAndValues ...interface{}) context.Context {
	if len(keyAndValues)%2 != 0 {
		return ctx
	}

	for i := 0; i < len(keyAndValues); i += 2 {
		ctx = context.WithValue(ctx, keyAndValues[i], keyAndValues[i+1])
	}

	return ctx
}
