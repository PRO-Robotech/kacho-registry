-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- Базовая схема kacho-registry (схема kacho_registry). Плоские ресурсы (без
-- K8s-envelope). БД хранит ТОЛЬКО метаданные namespace-реестра; блобы/манифесты
-- живут в zot (source of truth). Within-service инварианты — на DB-уровне
-- (partial UNIQUE / CHECK), без software check-then-act.

CREATE SCHEMA IF NOT EXISTS kacho_registry;
SET search_path TO kacho_registry, public;

-- ---------------------------------------------------------------------------
-- registries — tenant-namespace реестра образов. id (prefix "reg") — immutable
-- PK; project_id — cross-domain ref на kacho-iam (TEXT, БЕЗ FK: DB-per-service);
-- name — DNS-safe, UNIQUE среди ЖИВЫХ реестров project'а. labels участвуют в
-- authz label-scoping. status ∈ {ACTIVE, DELETING} (DELETING терминальный).
-- ---------------------------------------------------------------------------
CREATE TABLE registries (
  id          TEXT         PRIMARY KEY,                 -- "reg..." (ids.NewID)
  project_id  TEXT         NOT NULL,                    -- cross-domain (iam), без FK
  name        TEXT         NOT NULL,
  description TEXT         NOT NULL DEFAULT '',
  labels      JSONB        NOT NULL DEFAULT '{}'::jsonb,
  status      TEXT         NOT NULL DEFAULT 'ACTIVE',
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  CONSTRAINT registries_status_check CHECK (status IN ('ACTIVE', 'DELETING')),
  CONSTRAINT registries_labels_object_ck CHECK (jsonb_typeof(labels) = 'object')
);

-- partial UNIQUE: name уникально среди ЖИВЫХ (не-DELETING) реестров project'а.
-- Имя, освобождённое переходом предыдущего реестра в DELETING, немедленно
-- доступно для повторного Create (23505 только против ACTIVE-дубля).
CREATE UNIQUE INDEX registries_project_name_live_uq
  ON registries (project_id, name) WHERE status <> 'DELETING';

-- cursor-index (project_id, created_at, id) — курсорная пагинация List.
CREATE INDEX registries_project_cursor_idx ON registries (project_id, created_at, id);

-- GIN на labels — label-scoping authz-фильтра.
CREATE INDEX registries_labels_gin_idx ON registries USING gin (labels);

-- ---------------------------------------------------------------------------
-- registry_outbox — transactional-outbox owner-tuple (fga-proxy). Намерение
-- RegisterResource/UnregisterResource owner-hierarchy-tuple созданного/удалённого
-- реестра пишется строкой в той же writer-tx, что INSERT/DELETE (один commit,
-- no dual-write). Отдельный register-drainer (corelib outbox/drainer,
-- FOR UPDATE SKIP LOCKED) применяет строку через kacho-iam InternalIAMService по
-- mTLS (идемпотентно, at-least-once). Схема совместима с corelib outbox/drainer.
-- ---------------------------------------------------------------------------
CREATE TABLE registry_outbox (
  id            BIGSERIAL    PRIMARY KEY,
  -- event_type ∈ {fga.register, fga.unregister}. CHECK — против typo caller'а.
  event_type    TEXT         NOT NULL,
  -- payload — JSON-сериализованный набор tuple-намерений ресурса.
  payload       JSONB        NOT NULL,
  resource_kind TEXT         NOT NULL DEFAULT '',
  resource_id   TEXT         NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  -- sent_at IS NULL → pending; NOT NULL → applied (drainer mark'нул).
  sent_at       TIMESTAMPTZ,
  last_error    TEXT,
  -- attempt_count — попытки drainer'а; ≥ MaxAttempts → poisoned-skip.
  attempt_count INTEGER      NOT NULL DEFAULT 0,
  CONSTRAINT registry_outbox_event_type_check
    CHECK (event_type = ANY (ARRAY['fga.register'::text, 'fga.unregister'::text])),
  CONSTRAINT registry_outbox_payload_object_ck
    CHECK (jsonb_typeof(payload) = 'object'::text)
);

-- Partial index на pending-rows — drainer claim'ит только sent_at IS NULL.
CREATE INDEX registry_outbox_pending_idx
  ON registry_outbox (id) WHERE sent_at IS NULL;

-- +goose StatementBegin
-- register-drainer LISTEN'ит канал и wake-up'ится без poll-задержки.
CREATE FUNCTION registry_outbox_notify() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('kacho_registry_outbox', NEW.id::text);
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER registry_outbox_notify_trg AFTER INSERT ON registry_outbox
  FOR EACH ROW EXECUTE FUNCTION registry_outbox_notify();

-- ---------------------------------------------------------------------------
-- operations — Long-Running Operations (LRO) каталога kacho-registry. Мутации
-- Create/Update/Delete/DeleteTag/TriggerGarbageCollection асинхронны: RPC
-- возвращает строку operations (done=false), corelib-worker выполняет доменную
-- запись и финализирует строку (done=true, response=Registry/Empty либо
-- error=google.rpc.Status). Клиент поллит OperationService.Get(id) до done.
-- Набор колонок совпадает с corelib operations.Repo (pgRepo).
-- ---------------------------------------------------------------------------
CREATE TABLE operations (
  id            TEXT         PRIMARY KEY,  -- "<registry-prefix><crockford>" для opsproxy
  description   TEXT         NOT NULL,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  created_by    TEXT         NOT NULL DEFAULT 'anonymous',
  modified_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  done          BOOLEAN      NOT NULL DEFAULT false,
  metadata_type TEXT,                       -- type_url из Any
  metadata_data BYTEA,                      -- value из Any
  resource_id   TEXT,                       -- денорм для filter в List
  account_id    TEXT,                       -- денорм (corelib INSERT-ит безусловно)
  error_code    INTEGER,
  error_message TEXT,
  error_details BYTEA,                       -- google.rpc.Status.details (Any[])
  response_type TEXT,
  response_data BYTEA,
  principal_type         TEXT NOT NULL DEFAULT 'system',
  principal_id           TEXT NOT NULL DEFAULT 'bootstrap',
  principal_display_name TEXT NOT NULL DEFAULT 'System'
);

CREATE INDEX operations_resource_idx   ON operations (resource_id);
CREATE INDEX operations_done_idx       ON operations (done);
CREATE INDEX operations_created_at_idx ON operations (created_at);
CREATE INDEX operations_account_id_idx
  ON operations (account_id, created_at, id)
  WHERE account_id IS NOT NULL;

-- Реестры заводятся тенантами через RegistryService.Create — встроенного seed нет.

-- +goose Down
SET search_path TO kacho_registry, public;
DROP INDEX IF EXISTS operations_account_id_idx;
DROP TABLE IF EXISTS operations;
DROP TRIGGER IF EXISTS registry_outbox_notify_trg ON registry_outbox;
DROP FUNCTION IF EXISTS registry_outbox_notify();
DROP TABLE IF EXISTS registry_outbox;
DROP TABLE IF EXISTS registries;
DROP SCHEMA IF EXISTS kacho_registry;
