FROM golang:1.25.10-alpine AS build

WORKDIR /workspace/plystra

COPY contracts/go.mod contracts/go.sum /workspace/contracts/
COPY plystra/go.mod plystra/go.sum ./
COPY system-admin/go.mod system-admin/go.sum /workspace/system-admin/
COPY system-audit/go.mod system-audit/go.sum /workspace/system-audit/
COPY system-authz/go.mod system-authz/go.sum /workspace/system-authz/
COPY system-identity/go.mod system-identity/go.sum /workspace/system-identity/
COPY system-resource-registry/go.mod system-resource-registry/go.sum /workspace/system-resource-registry/
RUN go mod download

COPY contracts /workspace/contracts
COPY system-admin /workspace/system-admin
COPY system-audit /workspace/system-audit
COPY system-authz /workspace/system-authz
COPY system-identity /workspace/system-identity
COPY system-resource-registry /workspace/system-resource-registry
COPY plystra .
RUN go run entgo.io/ent/cmd/ent generate ./ent/schema \
	&& CGO_ENABLED=0 GOOS=linux go build -o /out/plystrad ./cmd/plystrad \
	&& CGO_ENABLED=0 GOOS=linux go build -o /out/plystractl ./cmd/plystractl \
	&& chmod +x ./scripts/build-capabilities.sh \
	&& CGO_ENABLED=0 GOOS=linux ./scripts/build-capabilities.sh \
	&& mkdir -p /out/app \
	&& cp -R capabilities /out/app/capabilities

FROM alpine:3.22

RUN addgroup -S plystra && adduser -S plystra -G plystra
WORKDIR /app

COPY --from=build /out/plystrad /usr/local/bin/plystrad
COPY --from=build /out/plystractl /usr/local/bin/plystractl
COPY plystra/migrations ./migrations
COPY --from=build --chown=plystra:plystra /out/app/capabilities ./capabilities

ENV PLYSTRA_SYSTEM_CAPABILITIES_CONFIG=/app/capabilities/system-capabilities.yaml \
	PLYSTRA_LOCKFILE=/app/capabilities/plystra.lock

USER plystra
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null || exit 1
CMD ["plystrad"]
