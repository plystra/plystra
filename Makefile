DATABASE_URL ?= postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable
SERVER_PORT ?= 8080

.PHONY: run migrate seed-demo demo demo-trace demo-reset ent-status ent-plan ent-check ent-apply ent-generate openapi test fmt

run:
	DATABASE_URL="$(DATABASE_URL)" SERVER_PORT="$(SERVER_PORT)" go run ./cmd/plystrad

migrate:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/plystractl migrate up

seed-demo: migrate
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/plystractl admin bootstrap-super-admin --user-id user_alice --member-id member_finance_reviewer --grant-id ag_alice_local_demo_instance_super_admin --if-exists ok

demo: seed-demo
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/explain-demo

demo-trace: demo

demo-reset:
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

test:
	go test ./...

fmt:
	gofmt -w cmd internal ent/schema
