-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- repository_configs — config-overlay ПЕРВОГО КЛАССА над OCI-репозиторием (RG-1).
--
-- Сегодня Repository — read-only проекция движка (source of truth = zot):
-- появляется register-on-first-push, исчезает unregister-on-last-tag, своей строки
-- в БД нет. Overlay вводит DB-owned строку, ключуемую НАТУРАЛЬНЫМ ключом
-- (registry_id, name) — НЕ генерируемым id-prefix (сохраняем проекционную модель).
-- Overlay ⟂ projection: строка здесь «переживает пустоту» (durable-repo виден с
-- tagCount=0), НЕ ломая register-on-first-push / unregister-on-last-tag (ephemeral).
--
-- Within-service инварианты — ТОЛЬКО на DB-уровне (ban #10, data-integrity.md):
--   * uniqueness (registry_id, name)  → PRIMARY KEY (registry_id, name);
--   * visibility-домен {PRIVATE,PUBLIC} → CHECK (fail-safe дефолт PRIVATE);
--   * ссылочная целостность на реестр  → FK registry_id → registries(id)
--     ON DELETE CASCADE (SAME-DB cascade — реестр сносит свои overlay; ban #4 —
--     это НЕ cross-service cascade, обе таблицы в схеме kacho_registry).
-- Rename = ОДНОСТЕЙТМЕНТНАЯ запись целевого имени под PK-backstop: re-key UPDATE
-- (durable) либо INSERT (ephemeral auto-promote) — оба ловят занятое имя как 23505.
SET search_path TO kacho_registry, public;

CREATE TABLE repository_configs (
  registry_id TEXT        NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  name        TEXT        NOT NULL,
  description TEXT        NOT NULL DEFAULT '',
  labels      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  -- visibility authoritative на overlay, дефолт PRIVATE (fail-safe). Переход →PUBLIC
  -- подчинён any-path-to-PUBLIC admin-gate (D-6) — это use-case-инвариант, не DB.
  visibility  TEXT        NOT NULL DEFAULT 'PRIVATE',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Натуральный ключ (registry_id, name): арбитр дубликата Create/rename-collision.
  PRIMARY KEY (registry_id, name),
  CONSTRAINT repository_configs_visibility_check
    CHECK (visibility IN ('PRIVATE', 'PUBLIC')),
  CONSTRAINT repository_configs_labels_object_ck
    CHECK (jsonb_typeof(labels) = 'object')
);

-- cursor-index (registry_id, created_at, name) — курсорная пагинация overlay-стороны
-- ListRepositories (overlay ⊔ projection union строится в use-case).
CREATE INDEX repository_configs_cursor_idx
  ON repository_configs (registry_id, created_at, name);

-- GIN на labels — label-scoping/filter parity с registries.
CREATE INDEX repository_configs_labels_gin_idx
  ON repository_configs USING gin (labels);

-- registries.default_visibility — сид visibility для НОВЫХ repo (mutable через
-- UpdateRegistry; переход →PUBLIC подчинён тому же any-path-to-PUBLIC admin-gate,
-- что и per-repo visibility, D-6). Дефолт PRIVATE (fail-safe).
ALTER TABLE registries
  ADD COLUMN default_visibility TEXT NOT NULL DEFAULT 'PRIVATE';
ALTER TABLE registries
  ADD CONSTRAINT registries_default_visibility_check
    CHECK (default_visibility IN ('PRIVATE', 'PUBLIC'));

-- +goose Down
SET search_path TO kacho_registry, public;
ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_default_visibility_check;
ALTER TABLE registries DROP COLUMN IF EXISTS default_visibility;
DROP TABLE IF EXISTS repository_configs;
