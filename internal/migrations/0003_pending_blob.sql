-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- registry_pending_blob — durable per-repo учёт фактически загруженных блобов
-- (REG-33 Defect A: #33). На первом push docker пишет блобы ДО манифеста, поэтому
-- только-что-загруженный слой не входит ни в один манифест repo → BlobInRepo=false →
-- push-time HEAD блоба возвращал 404 («unknown blob») на блоб, который docker только что
-- успешно запушил (201). Эта таблица фиксирует (registry_id, repo, digest) на успешном
-- blob PUT-finalize, чтобы serveBlob раскрыл именно этот блоб ДО появления манифеста —
-- НЕ пере-открывая cross-tenant blob-leak: zot дедуплицирует content-addressable блобы
-- глобально (HEAD чужого глобального блоба из любого repo даёт 200; проверено
-- эмпирически на zot v2.1.18). REG-37 сохранён — раскрываются только блобы, которые
-- авторизованный writer доказуемо загрузил в ЭТОТ repo (zot проверил digest на finalize).
--
-- Строка живёт короткий TTL (freshness): после появления блоба в манифесте BlobInRepo
-- становится true и строка избыточна; sweeper подметает протухшие. PK — естественный
-- составной ключ (registry_id, repo, digest); INSERT ... ON CONFLICT DO UPDATE
-- (idемпотентный upsert) освежает uploaded_at на повторном аплоаде того же слоя.

SET search_path TO kacho_registry, public;

CREATE TABLE registry_pending_blob (
  registry_id TEXT        NOT NULL,
  repo        TEXT        NOT NULL,
  digest      TEXT        NOT NULL,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (registry_id, repo, digest)
);

-- Индекс по uploaded_at — TTL-sweep (DELETE ... WHERE uploaded_at <= cutoff) и
-- freshness-предикат BlobUploaded (uploaded_at > cutoff) без seq-scan.
CREATE INDEX registry_pending_blob_uploaded_at_idx
  ON registry_pending_blob (uploaded_at);

-- +goose Down
SET search_path TO kacho_registry, public;
DROP INDEX IF EXISTS registry_pending_blob_uploaded_at_idx;
DROP TABLE IF EXISTS registry_pending_blob;
