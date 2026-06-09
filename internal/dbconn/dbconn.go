package dbconn

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

const defaultSearchPath = "public"

func ParseConfig(databaseURL string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	applyRuntimeDefaults(cfg.RuntimeParams)
	return cfg, nil
}

func OpenDB(databaseURL string) (*sql.DB, error) {
	cfg, err := ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	return stdlib.OpenDB(*cfg), nil
}

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	applyRuntimeDefaults(cfg.ConnConfig.RuntimeParams)
	return pgxpool.NewWithConfig(ctx, cfg)
}

func applyRuntimeDefaults(params map[string]string) {
	if _, exists := params["search_path"]; !exists {
		params["search_path"] = defaultSearchPath
	}
}
