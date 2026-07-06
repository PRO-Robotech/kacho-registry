// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import "github.com/kelseyhightower/envconfig"

// Load заполняет структуру c значениями из переменных окружения.
// Использует envconfig с пустым префиксом — ожидаются полные имена переменных.
func Load(c any) error { return envconfig.Process("", c) }

// LoadPrefixed заполняет структуру c значениями из переменных окружения,
// используя prefix как корневой сегмент имен (KACHO_<DOMAIN>). Имя каждой
// переменной выводится из иерархии полей: prefix + имя вложенного поля + ... .
//
// Это позволяет встраивать ГОРИЗОНТАЛЬНЫЕ value-структуры corelib (например
// grpcsrv.TLSServer / grpcclient.TLSClient) под per-edge полями сервиса без
// абсолютных envconfig-тегов: имя env выводится из имени родительского поля,
// поэтому два инстанса одной структуры под разными полями получают НЕЗАВИСИМЫЕ,
// per-edge-префиксованные переменные. Сервис сам владеет именованием
// ребра через имя поля, а не структура corelib через зашитый тег.
func LoadPrefixed(prefix string, c any) error { return envconfig.Process(prefix, c) }
