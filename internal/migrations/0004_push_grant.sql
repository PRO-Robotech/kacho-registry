-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- registry_push_grant — durable per-subject учёт push-ownership репозитория (REG-33
-- immediate-pull: #33). После успешного manifest-PUT нового repo per-object
-- registry_repository authz материализуется АСИНХРОННО (register-on-first-push →
-- registry_outbox → fga-proxy drainer → IAM RegisterResource → FGA reconciler). Пока это
-- окно не догнало (эмпирически ~10-15s на проде), собственный `docker pull` толкавшего
-- упирается в v_get@registry_repository-deny → 404 («name unknown»), хотя push прошёл (201).
-- Эта таблица фиксирует (registry_id, repo, subject) на успешном manifest-PUT, чтобы
-- pull-path раскрыл repo ИМЕННО толкавшему как fallback, пока FGA не материализовал v_get.
--
-- Ключ по SUBJECT — раскрывается ТОЛЬКО собственный только-что-запушенный repo толкавшего:
-- чужой субъект/тенант записи не имеет → остаётся 404 (REG-37 сохранён, cross-tenant leak
-- невозможен). serveBlob дополнительно держит blob-scope (BlobInRepo / pending-blob): push-
-- grant раскрывает repo, но НЕ произвольный глобальный content-addressable блоб.
--
-- Строка живёт TTL (freshness): как только FGA материализует v_get, штатный путь обслуживает
-- repo и запись избыточна; sweeper подметает протухшие. PK — естественный составной ключ
-- (registry_id, repo, subject); INSERT ... ON CONFLICT DO UPDATE (идемпотентный upsert)
-- освежает granted_at на повторном push того же субъекта в тот же repo (re-push держит
-- запись свежей всё push-окно). Зеркалит registry_pending_blob (миграция 0003).

SET search_path TO kacho_registry, public;

CREATE TABLE registry_push_grant (
  registry_id TEXT        NOT NULL,
  repo        TEXT        NOT NULL,
  subject     TEXT        NOT NULL,
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (registry_id, repo, subject)
);

-- Индекс по granted_at — TTL-sweep (DELETE ... WHERE granted_at <= cutoff) и
-- freshness-предикат PushGranted (granted_at > cutoff) без seq-scan.
CREATE INDEX registry_push_grant_granted_at_idx
  ON registry_push_grant (granted_at);

-- +goose Down
SET search_path TO kacho_registry, public;
DROP INDEX IF EXISTS registry_push_grant_granted_at_idx;
DROP TABLE IF EXISTS registry_push_grant;
