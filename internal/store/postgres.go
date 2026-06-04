package store

import (
	"context"

	"github.com/plystra/core/internal/store/entstore"
)

// PostgresStore is kept as a compatibility alias for older internal callers.
// All PostgreSQL-backed store operations are implemented by Ent.
type PostgresStore = entstore.Store

func OpenPostgres(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	return entstore.Open(ctx, databaseURL)
}
