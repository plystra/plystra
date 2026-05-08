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

Non-public API routes require a Bearer session for a user with an active admin grant. The demo seed makes Alice the local instance super admin:

```powershell
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/login -ContentType "application/json" -Body '{"email":"alice@example.com","password":"plystra-demo"}'
$token = $login.data.access_token
Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } http://localhost:8080/api/v1/admin/me
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
