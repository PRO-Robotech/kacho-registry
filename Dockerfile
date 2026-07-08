# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# Multi-stage cross-compile build для kacho-registry (api-server + migrator).
#
# NOTE (build-context): go.mod держит `replace github.com/PRO-Robotech/kacho-corelib
# => ../kacho-corelib` (локальная polyrepo-разработка). Standalone `docker build`
# из этого репо требует, чтобы внутренние зависимости резолвились: либо переключить
# go.mod на GitHub-версии (публикационная фаза), либо собирать из parent-context с
# COPY ../kacho-corelib и go.work. По умолчанию цель — single-repo build с
# versioned-модулями (COPY . . + go mod download).
FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY . .
RUN go mod download
# Два независимых бинаря в одном образе:
#   kacho-registry — control-plane gRPC-сервер (`serve`).
#   kacho-migrator — CLI миграций (up|down|status); запускается deploy-init-контейнером.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-registry ./cmd/kacho-registry \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-migrator ./cmd/migrator

FROM mirror.gcr.io/library/alpine:3.20
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=builder /kacho-registry /usr/local/bin/kacho-registry
COPY --from=builder /kacho-migrator /usr/local/bin/kacho-migrator
USER 65532
ENTRYPOINT ["/usr/local/bin/kacho-registry"]
CMD ["serve"]
