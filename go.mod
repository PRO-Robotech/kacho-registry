module github.com/PRO-Robotech/kacho-registry

go 1.26.4

require (
	github.com/PRO-Robotech/kacho-corelib v1.0.2
	github.com/PRO-Robotech/kacho-iam v1.0.2
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
	github.com/jackc/pgx/v5 v5.9.2
	github.com/pressly/goose/v3 v3.27.1
	google.golang.org/genproto/googleapis/api v0.0.0-20260427160629-7cedc36a6bc4
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260427160629-7cedc36a6bc4 // indirect
)

// Локальная polyrepo-разработка: kacho-corelib берётся из соседнего репо (не
// versioned-модуль с GitHub). Для standalone-сборки/Docker переключить на
// pseudo-version с GitHub (публикационная фаза) либо использовать go.work.
replace github.com/PRO-Robotech/kacho-corelib => ../kacho-corelib
