package gomod

import (
	"context"

	"github.com/maksemen2/trustmod/internal/command"
)

type offlineContextKey struct{}

func WithOffline(ctx context.Context) context.Context {
	return context.WithValue(ctx, offlineContextKey{}, true)
}

func IsOffline(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	offline, _ := ctx.Value(offlineContextKey{}).(bool)
	return offline
}

func commandContext(ctx context.Context) context.Context {
	if !IsOffline(ctx) {
		return ctx
	}
	return command.WithEnv(ctx,
		"GOPROXY=off",
		"GOSUMDB=off",
		"GONOSUMDB=*",
	)
}
