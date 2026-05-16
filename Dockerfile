FROM golang:1.25.10-alpine AS build

WORKDIR /workspace/plystra
COPY plystra/go.mod plystra/go.sum ./
COPY kernel/go.mod /workspace/kernel/go.mod
COPY system-admin/go.mod /workspace/system-admin/go.mod
COPY system-audit/go.mod /workspace/system-audit/go.mod
COPY system-authz/go.mod /workspace/system-authz/go.mod
COPY system-identity/go.mod /workspace/system-identity/go.mod
COPY system-resource-registry/go.mod /workspace/system-resource-registry/go.mod
RUN go mod download

COPY kernel /workspace/kernel
COPY system-admin /workspace/system-admin
COPY system-audit /workspace/system-audit
COPY system-authz /workspace/system-authz
COPY system-identity /workspace/system-identity
COPY system-resource-registry /workspace/system-resource-registry
COPY plystra .
RUN go run entgo.io/ent/cmd/ent generate ./ent/schema \
	&& CGO_ENABLED=0 GOOS=linux go build -o /out/plystrad ./cmd/plystrad \
	&& CGO_ENABLED=0 GOOS=linux go build -o /out/plystractl ./cmd/plystractl

FROM alpine:3.22

RUN addgroup -S plystra && adduser -S plystra -G plystra
WORKDIR /app

COPY --from=build /out/plystrad /usr/local/bin/plystrad
COPY --from=build /out/plystractl /usr/local/bin/plystractl
COPY plystra/migrations ./migrations

USER plystra
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null || exit 1
CMD ["plystrad"]
