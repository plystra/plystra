# Plystra Core

Self-hosted identity and authorization core for account-identity separation, scoped permissions, and explainable audit logs.

```text
User -> UserMember -> Member -> Space
```

This repository contains only the Core service, Ent schemas, migrations, CLI tools, OpenAPI contract, and tests. Product docs, integration guides, release notes, and operations guides live in the sibling documentation site: `../plystra-docs`.

## Quick Start

```powershell
cp .env.example .env
docker compose up -d postgres
go run .\cmd\plystractl migrate up
go run .\cmd\plystractl migrate verify
go run .\cmd\plystractl ent check
go run .\cmd\plystractl doctor
go test ./...
go run .\cmd\explain-demo
go run .\cmd\plystrad
```

Default local database URL:

```powershell
$env:PLYSTRA_DATABASE_URL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"
```

Non-public API routes require the bootstrap admin token:

```http
X-Plystra-Admin-Token: <PLYSTRA_ADMIN_TOKEN>
```

## Development

```powershell
go generate ./ent
go test ./...
go run .\cmd\plystractl migrate verify
go run .\cmd\plystractl ent check
go run .\cmd\plystractl doctor
```

The Core API runs on `http://localhost:8080` by default. The admin console is in `../console`, and the documentation site is in `../plystra-docs`.

## Documentation

Run the docs site:

```powershell
cd ..\plystra-docs
npm install
npm run dev
```

Run the admin console:

```powershell
cd ..\console
npm install
npm run dev
```
