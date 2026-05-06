DATABASE_URL ?= postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable

.PHONY: migrate demo test fmt

migrate:
	docker compose exec -T postgres psql -U plystra -d plystra < migrations/001_finance_demo.sql

demo:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/explain-demo

test:
	go test ./...

fmt:
	gofmt -w cmd internal
