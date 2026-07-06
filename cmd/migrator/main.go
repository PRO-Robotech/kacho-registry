// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Command kacho-migrator — раннер DB-миграций kacho-registry (схема
// kacho_registry). Отдельный бинарь от API-сервера; запускается
// deploy-init-контейнером до старта основного pod.
//
//	kacho-migrator up|down|status
//
// DSN: флаг --dsn, иначе KACHO_MIGRATOR_DSN, иначе config kacho-registry (KACHO_REGISTRY_*).
package main

import (
	"database/sql"
	"flag"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib" // регистрирует database/sql-драйвер "pgx"
	"github.com/pressly/goose/v3"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-registry/internal/migrations"
)

func main() {
	dsnFlag := flag.String("dsn", "", "database DSN (else KACHO_MIGRATOR_DSN, else KACHO_REGISTRY_* config)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("usage: kacho-migrator [--dsn <dsn>] {up|down|status}")
	}
	direction := args[0]

	dsn := resolveDSN(*dsnFlag)

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("goose dialect: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var gerr error
	switch direction {
	case "up":
		gerr = goose.Up(db, ".")
	case "down":
		gerr = goose.Down(db, ".")
	case "status":
		gerr = goose.Status(db, ".")
	default:
		log.Fatalf("unknown migrate direction: %s (up|down|status)", direction)
	}
	if gerr != nil {
		log.Fatalf("migrate %s: %v", direction, gerr)
	}
}

// resolveDSN выбирает DSN: флаг --dsn > env KACHO_MIGRATOR_DSN > config kacho-registry.
func resolveDSN(flagDSN string) string {
	if flagDSN != "" {
		return flagDSN
	}
	if env := os.Getenv("KACHO_MIGRATOR_DSN"); env != "" {
		return env
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config (for DSN): %v", err)
	}
	return cfg.MigrateDSN()
}
