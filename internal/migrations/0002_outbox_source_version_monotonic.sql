-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- source_version мигрирует с to_jsonb(now()) на BIGSERIAL id самой outbox-строки.
--
-- Проблема: раньше source_version штамповался в Go-INSERT'е как to_jsonb(now()).
-- now() == transaction_timestamp() фиксируется на BEGIN транзакции, НЕ на commit'е.
-- Под конкуренцией двух Update-воркеров одного реестра (сериализованных row-lock'ом
-- на registries) source_version мог оказаться в ОБРАТНОМ commit-порядку: воркер,
-- начавший транзакцию раньше (меньший now()), но захвативший row-lock и закоммитивший
-- позже, нёс МЕНЬШИЙ маркер → last-source-state-wins в iam-mirror мог отбросить
-- реально финальное состояние (реверт label-scope к устаревшему).
--
-- Фикс: source_version = id самой outbox-строки (BIGSERIAL). id присваивается из
-- последовательности при INSERT'е внутри той же сериализованной writer-tx: воркер,
-- закоммитивший позже, обязательно выполнил свой INSERT позже (его UPDATE registries
-- ждал row-lock первого) → получил БОЛЬШИЙ id. Маркер строго монотонен commit-порядку
-- одного объекта и numeric (а не строкой-timestamp, лексикографически некорректной).
--
-- BEFORE INSERT trigger видит NEW.id уже заполненным (DEFAULT nextval применяется до
-- BEFORE-триггеров), поэтому может вписать его в payload перед материализацией строки.

-- +goose StatementBegin
CREATE FUNCTION kacho_registry.registry_outbox_stamp_source_version() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  NEW.payload := jsonb_set(NEW.payload, '{source_version}', to_jsonb(NEW.id));
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER registry_outbox_stamp_source_version_trg
  BEFORE INSERT ON kacho_registry.registry_outbox
  FOR EACH ROW EXECUTE FUNCTION kacho_registry.registry_outbox_stamp_source_version();

-- +goose Down
DROP TRIGGER IF EXISTS registry_outbox_stamp_source_version_trg ON kacho_registry.registry_outbox;
DROP FUNCTION IF EXISTS kacho_registry.registry_outbox_stamp_source_version();
