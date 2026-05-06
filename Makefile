DATABASE_URL ?= postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable

.PHONY: migrate demo test fmt

migrate:
	go run ./cmd/plystractl migrate up

demo:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/explain-demo

test:
	go test ./...

fmt:
	gofmt -w cmd internal
