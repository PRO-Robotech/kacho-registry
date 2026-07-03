# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

BINARY         := kacho-registry
CMD            := ./cmd/kacho-registry
MIGRATOR_BIN   := kacho-migrator
MIGRATOR_CMD   := ./cmd/migrator
IMAGE          := kacho-registry:dev

.PHONY: build build-migrator test test-short vet lint docker sync-migrations audit-list-filter

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) $(CMD)

build-migrator:
	CGO_ENABLED=0 go build -o bin/$(MIGRATOR_BIN) $(MIGRATOR_CMD)

# test — unit + integration (testcontainers Postgres). При contention гнать с
# -p 1 (локально DOCKER_HOST=colima).
test:
	go test ./... -race -cover -timeout 900s

test-short:
	go test ./... -race -cover -short -timeout 120s

vet:
	go vet ./...

lint:
	golangci-lint run ./...

docker:
	docker build -f Dockerfile -t $(IMAGE) .

# sync-migrations — синхронизирует common-миграции из kacho-corelib (operations
# table и т. п.), когда они выделены в общий набор. Текущий скелет держит
# operations в 0001_init.sql; цель — анкер под переход на общий набор corelib.
CORELIB_MIGRATIONS ?= ../kacho-corelib/migrations/common
sync-migrations:
	@test -d "$(CORELIB_MIGRATIONS)" || { echo "corelib common migrations не найдены: $(CORELIB_MIGRATIONS)"; exit 0; }
	@mkdir -p internal/migrations/common
	@cp -v "$(CORELIB_MIGRATIONS)"/* internal/migrations/common/ 2>/dev/null || true

# audit-list-filter — CI-гейт listauthz: публичный List обязан фильтровать выдачу
# (viewer∪v_list). Наполняется вместе с реализацией List (rpc-implementer).
audit-list-filter:
	@echo "audit-list-filter: реализуется вместе с RegistryService.List (rpc-implementer)"

.PHONY: migrate-up migrate-down migrate-status
migrate-up: build-migrator
	KACHO_REGISTRY_DB_PASSWORD=secret bin/$(MIGRATOR_BIN) up

migrate-down: build-migrator
	KACHO_REGISTRY_DB_PASSWORD=secret bin/$(MIGRATOR_BIN) down

migrate-status: build-migrator
	KACHO_REGISTRY_DB_PASSWORD=secret bin/$(MIGRATOR_BIN) status
