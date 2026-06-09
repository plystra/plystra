DATABASE_URL ?= postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable
SERVER_PORT ?= 8080

.PHONY: run migrate ent-status ent-plan ent-check ent-apply ent-generate openapi atlas-hash verify-generated test fmt

run:
	DATABASE_URL="$(DATABASE_URL)" SERVER_PORT="$(SERVER_PORT)" go run ./cmd/plystrad

migrate:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/plystractl migrate up

ent-status:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/plystractl ent status

ent-plan:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/plystractl ent plan

ent-check:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/plystractl ent check

ent-apply:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/plystractl ent apply

ent-generate:
	go run entgo.io/ent/cmd/ent generate ./ent/schema

openapi:
	go run ./cmd/plystra-openapi -out openapi

atlas-hash:
	go run ./cmd/plystractl migrate hash

verify-generated: ent-generate openapi atlas-hash
	git diff --exit-code -- ent openapi migrations/atlas.sum

test:
	go test ./...

fmt:
	gofmt -w cmd internal ent/schema
