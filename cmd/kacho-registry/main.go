// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Command kacho-registry — control-plane gRPC реестра образов (Registry).
//
// Leaf-сервис: по build не зависит ни от чего в Kachō, в runtime — consumer
// authz Check у kacho-iam + data-proxy к zot. Публичный :9090 —
// RegistryService (Registry CRUD + проекции repos/tags из zot); cluster-internal
// :9091 — InternalRegistryService (GC / stats), никогда не на внешнем TLS
// endpoint (только cluster-internal). Оба листенера несут per-RPC authz Check.
package main

import (
	"log"
	"os"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/config"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: kacho-registry {serve}")
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	switch os.Args[1] {
	case "serve":
		if err := runServe(cfg); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown command: %s (migrations: use the kacho-migrator binary)", os.Args[1])
	}
}
