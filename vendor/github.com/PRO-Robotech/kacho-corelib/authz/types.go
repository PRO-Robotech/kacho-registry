// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authz

import (
	"errors"
	"fmt"
)

// ObjectExtractor извлекает (object_type, object_id) из request'а конкретного
// RPC.
//
// Для типичных RPC (Get/Update/Delete на ресурс) — возвращает фиксированный
// object_type из RPCEntry и динамический object_id из request'а (например
// `GetNetworkRequest.network_id`).
//
// Для scope-conditional RPC (например `iam.AccessBindingService.Upsert`, где
// scope в request: account / project / resource) — возвращает оба значения
// зависимо от полей request'а.
type ObjectExtractor func(req any) (objectType string, objectID string, err error)

// StaticExtractor — helper для типичного случая, когда object_type фиксирован
// в RPCEntry, а ID extract'ится из конкретного поля request'а.
//
// Пример:
//
//	"/kacho.cloud.vpc.v1.NetworkService/Get": {
//	    Relation: "viewer",
//	    Extract:  authz.StaticExtractor("vpc_network", func(req any) (string, error) {
//	        return req.(*vpcv1.GetNetworkRequest).GetNetworkId(), nil
//	    }),
//	},
func StaticExtractor(objectType string, extractID func(req any) (string, error)) ObjectExtractor {
	return func(req any) (string, string, error) {
		id, err := extractID(req)
		if err != nil {
			return "", "", err
		}
		return objectType, id, nil
	}
}

// RPCEntry — описание прав, требуемых на конкретный RPC.
//
// Заполняется в per-service `internal/metadata/permission_map.go`:
//
//	var PermissionMap = authz.RPCMap{
//	    "/kacho.cloud.vpc.v1.NetworkService/Get": {
//	        Relation: "viewer",
//	        Extract:  authz.StaticExtractor("vpc_network", ...),
//	    },
//	    ...
//	}
type RPCEntry struct {
	// Relation — FGA-relation, требуемое на object'е.
	// "viewer" | "editor" | "admin" | "use" | "start_stop" | etc.
	Relation string

	// Extract — функция, извлекающая (object_type, object_id) из request'а.
	// Возвращаемый objectType+":"+objectID составляет FGA object string.
	//
	// Для статичных object_type — используй StaticExtractor.
	// Для scope-conditional — пиши full ObjectExtractor.
	Extract ObjectExtractor

	// Public — если true, RPC освобожден от per-RPC tenant-authz Check
	// (exempt). Default false → Check энфорсится. Имя историческое: «public»
	// здесь означает «не требует tenant-authz» (напр. OperationService.Get,
	// который авторизуется на data-уровне), а не «доступен извне».
	//
	// Internal RPC, поднятый на :9091, ОБЯЗАН присутствовать в RPCMap: либо с
	// Relation (Check по своему tier), либо Public=true для явного exempt'а.
	// Не-замапленный RPC fail-closed — name-based исключений нет.
	Public bool

	// ScopeFiltered — если true, interceptor НЕ делает
	// single-object Check для этого RPC: RPC сам авторизует на data-уровне
	// (scope-filter List — handler через ListObjects резолвит allowed-set и
	// возвращает 200 + filtered, EMPTY если доступа нет; см.
	// authz.ListObjectsService). Единичный per-RPC Check здесь семантически
	// неверен — он отверг бы весь вызов `no path` 403 ДО того, как
	// scope-filter отработает.
	//
	// Отличие от Public: ScopeFiltered RPC — публичный, требует
	// аутентификации (валидный JWT на api-gateway); пропускается ТОЛЬКО
	// per-RPC authz-Check. Public — internal-RPC (запрет #6), вообще вне
	// tenant-authz. Mapping в `DecisionInternal` (skip) — общий, но смысл
	// разный, поэтому отдельное поле.
	ScopeFiltered bool

	// Permission — строка из permission-catalog в формате
	// `<module>.<resource>.<verb>` (напр. `loadbalancer.networkLoadBalancers.start`),
	// предназначена для будущего fine-grained Check.
	//
	// Сейчас interceptor ее НЕ читает — Check идет по полю Relation как
	// раньше. Permission заполняется параллельно в per-service
	// PermissionMap'ах, чтобы при переключении на fine-grained model
	// (relation → permission per RPC) был drop-in путь без переписывания
	// proto-stubs / extractors. Optional: zero-value ("") допустим и
	// означает «пока не каталогизировано».
	Permission string
}

// RPCMap — карта `<FullMethod>` → RPCEntry. Передается в Interceptor.
//
// FullMethod (grpc-go convention): "/<package>.<service>/<method>", напр.
// "/kacho.cloud.vpc.v1.NetworkService/Get".
type RPCMap map[string]RPCEntry

// Lookup возвращает RPCEntry, ok — если найден.
func (m RPCMap) Lookup(fullMethod string) (RPCEntry, bool) {
	e, ok := m[fullMethod]
	return e, ok
}

// PrincipalLike — узкий port-интерфейс для Principal'а. Используется
// interceptor'ом, чтобы не зависеть от operations.Principal напрямую (хотя
// и фактически он его реализует).
//
// Реализация — `operations.Principal` (поле .ID).
type PrincipalLike interface {
	GetID() string
}

// Decision — что interceptor решил сделать с RPC.
type Decision int

const (
	// DecisionAllowed — разрешено (Check вернул allowed=true или break-glass).
	DecisionAllowed Decision = iota
	// DecisionDenied — отказано (Check вернул allowed=false).
	DecisionDenied
	// DecisionUnavailable — FGA / kacho-iam недоступны (fail-closed).
	DecisionUnavailable
	// DecisionUnmapped — RPC не в RPCMap (fail-closed по умолчанию).
	DecisionUnmapped
	// DecisionInternal — RPC помечен Public=false / internal — пропуск.
	DecisionInternal
	// DecisionRateLimited — превышен per-Principal rate limit on denied storm.
	DecisionRateLimited
	// DecisionNoPath — FGA нет пути к ресурсу: ресурс, скорее всего, не существует
	// (нет hierarchy-tuple). Interceptor пропускает вызов к handler'у, который
	// вернет NOT_FOUND из DB. Инициируется, когда CheckClient.Check() возвращает
	// ErrNoPath.
	DecisionNoPath
	// DecisionHideExistence — object-scoped deny на СУЩЕСТВУЮЩИЙ ресурс, который
	// caller не вправе видеть. Interceptor БЛОКИРУЕТ handler (в отличие от
	// DecisionNoPath) и возвращает NOT_FOUND, скрывая факт существования
	// (existence-hiding): tenant без доступа не должен отличить «есть-но-не-твой»
	// от «нет такого». Инициируется, когда CheckClient.Check() возвращает
	// ErrHideExistence (клиент сам сверил наличие объекта в своей БД).
	DecisionHideExistence
)

// String — human-readable representation, используется в метриках / логах.
func (d Decision) String() string {
	switch d {
	case DecisionAllowed:
		return "allowed"
	case DecisionDenied:
		return "denied"
	case DecisionUnavailable:
		return "unavailable"
	case DecisionUnmapped:
		return "unmapped"
	case DecisionInternal:
		return "internal"
	case DecisionRateLimited:
		return "rate_limited"
	case DecisionNoPath:
		return "no_path"
	case DecisionHideExistence:
		return "hide_existence"
	}
	return "unknown"
}

// ErrUnmapped — RPC не покрыт RPCMap. Должен мапиться в `PermissionDenied`
// (fail-closed). Метрика `kacho_authz_unmapped_total{rpc=...}` инкрементируется.
var ErrUnmapped = errors.New("authz: RPC not mapped in PermissionMap")

// ErrUnavailable — FGA / kacho-iam.Check недоступны. fail-closed default.
var ErrUnavailable = errors.New("authz: check service unavailable")

// ErrPermissionDenied — FGA / kacho-iam отвергли запрос (gRPC PermissionDenied).
// Семантически отличается от ErrUnavailable: это легитимный denial subject'а,
// а НЕ инфраструктурная недоступность. Caller должен мапить на gRPC
// PermissionDenied (HTTP 403), а не Unavailable (HTTP 503) — иначе клиент
// (UI / SDK) не отличит "у тебя нет прав" от "сервис не работает", и retry-логика
// сделает хуже.
//
// Ранее listobjects.go оборачивал PermissionDenied
// в ErrUnavailable через `fmt.Errorf("%w: %v", ErrUnavailable, err)` —
// gRPC-код терялся в `%v`-formatting, caller'ы вынужденно возвращали 503.
var ErrPermissionDenied = errors.New("authz: permission denied")

// ErrNoPath — CheckClient.Check() sentinel: FGA вернул allowed=false с
// причиной "no path" (нет hierarchy-tuple для объекта). Означает: ресурс
// либо не существует, либо tuple еще не записан. Interceptor интерпретирует
// это как DecisionNoPath и пропускает RPC к handler'у, который вернет
// NOT_FOUND из DB.
//
// Используется только клиентами, которые имеют доступ к полю `reason`
// в CheckResponse (kacho-compute, kacho-vpc). Другие клиенты могут игнорировать.
var ErrNoPath = errors.New("authz: no FGA path to resource")

// ErrHideExistence — CheckClient.Check() sentinel: object-scoped deny на ресурс,
// который СУЩЕСТВУЕТ в БД сервиса, но caller не вправе его видеть. В отличие от
// ErrNoPath (passthrough → handler сам отдаст NOT_FOUND для отсутствующего),
// здесь объект есть — passthrough слил бы его. Interceptor БЛОКИРУЕТ handler и
// возвращает NOT_FOUND (existence-hiding): «есть-но-не-твой» неотличимо от «нет».
// Клиент возвращает этот sentinel, только сам сверив наличие объекта в своей БД.
var ErrHideExistence = errors.New("authz: hide existence (deny on existing object)")

// FormatObject форматирует FGA-object string: "<type>:<id>".
// Возвращает err если type/id содержат запрещенные символы (':', whitespace).
func FormatObject(objectType, objectID string) (string, error) {
	if objectType == "" {
		return "", fmt.Errorf("authz: empty object type")
	}
	if objectID == "" {
		return "", fmt.Errorf("authz: empty object id")
	}
	for _, r := range objectType {
		if r == ':' || r == ' ' || r == '\t' || r == '\n' {
			return "", fmt.Errorf("authz: invalid char in object type: %q", objectType)
		}
	}
	for _, r := range objectID {
		if r == ':' || r == ' ' || r == '\t' || r == '\n' {
			return "", fmt.Errorf("authz: invalid char in object id: %q", objectID)
		}
	}
	return objectType + ":" + objectID, nil
}

// FormatSubject форматирует FGA-subject string из Principal'а.
//
// Mapping:
//   - Principal{Type:"user", ID:"usr_xxx"}            → "user:usr_xxx"
//   - Principal{Type:"service_account", ID:"sva_xxx"} → "service_account:sva_xxx"
//   - Principal{Type:"system", ID:"bootstrap"}        → "user:bootstrap" (для аудита;
//     обычно system-principal обходит interceptor через internal-path).
//
// Group-principal'ы в этом mapping'е не появляются: для group-binding'ов FGA
// разрешает access через `group:<id>#member` tuple — но subject в Check всегда
// конкретный user / SA (resolved от Principal в auth-interceptor'е).
func FormatSubject(principalType, principalID string) string {
	if principalID == "" {
		// Защита от вырожденного случая; вызов с пустым ID — bug.
		principalID = "unknown"
	}
	switch principalType {
	case "user", "service_account":
		return principalType + ":" + principalID
	default:
		// system / anonymous / unknown — мапим как user (fallback аудит).
		return "user:" + principalID
	}
}
