package authz

import "context"

func Check(ctx context.Context, store Store, input CheckInput) (*Decision, error) {
	return NewEngine(store).Check(ctx, input)
}

func Explain(ctx context.Context, store Store, input CheckInput) (*Decision, error) {
	return Check(ctx, store, input)
}
