FROM golang:1.25.10-alpine AS build

WORKDIR /workspace/plystra

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go run entgo.io/ent/cmd/ent generate ./ent/schema \
	&& CGO_ENABLED=0 GOOS=linux go build -o /out/plystrad ./cmd/plystrad \
	&& CGO_ENABLED=0 GOOS=linux go build -o /out/plystractl ./cmd/plystractl

FROM alpine:3.22

RUN addgroup -S plystra && adduser -S plystra -G plystra
WORKDIR /app

COPY --from=build /out/plystrad /usr/local/bin/plystrad
COPY --from=build /out/plystractl /usr/local/bin/plystractl
COPY --from=build /workspace/plystra/migrations ./migrations

USER plystra
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null || exit 1
CMD ["plystrad"]
