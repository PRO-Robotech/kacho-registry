// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"

	corecfg "github.com/PRO-Robotech/kacho-corelib/config"
)

// LoadInto — test-only хелпер: выставляет переданные env-переменные на время вызова
// и грузит тем же путём LoadPrefixed, что и Load (по выходу восстанавливает env).
// Живёт в _test.go — не собирается в production-бинарь (мутация process-global env
// не concurrency-safe, вызывать из runtime-кода нельзя).
func LoadInto(c *Config, env map[string]string) error {
	saved := make(map[string]*string, len(env))
	for k, v := range env {
		if prev, ok := os.LookupEnv(k); ok {
			saved[k] = &prev
		} else {
			saved[k] = nil
		}
		_ = os.Setenv(k, v)
	}
	defer func() {
		for k, prev := range saved {
			if prev == nil {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, *prev)
			}
		}
	}()
	return corecfg.LoadPrefixed(envPrefix, c)
}
