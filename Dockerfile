# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# Multi-stage cross-compile build для kacho-registry (api-server + migrator).
#
# NOTE (vendored deps): внутренние зависимости (kacho-corelib, kacho-proto) живут в
# ПРИВАТНЫХ репозиториях, поэтому standalone `docker build` не может `go mod download`
# их без cross-repo git-auth в builder-образе (golang:alpine без git → proxy 404 →
# direct-git fallback падает `exec: "git": not found`). Вместо этого они закоммичены
# под vendor/ (`go mod vendor`), и сборка идёт полностью офлайн через `-mod=vendor` —
# без сети, git и proxy. Обновляй vendor/ командой `go mod vendor` при любой правке go.mod.
FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY . .
# Два независимых бинаря в одном образе:
#   kacho-registry — control-plane gRPC-сервер (`serve`).
#   kacho-migrator — CLI миграций (up|down|status); запускается deploy-init-контейнером.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -o /kacho-registry ./cmd/kacho-registry \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -o /kacho-migrator ./cmd/migrator

FROM mirror.gcr.io/library/alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /kacho-registry /usr/local/bin/kacho-registry
COPY --from=builder /kacho-migrator /usr/local/bin/kacho-migrator
USER 65532
ENTRYPOINT ["/usr/local/bin/kacho-registry"]
CMD ["serve"]
