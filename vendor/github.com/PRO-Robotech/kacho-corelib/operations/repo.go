// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package operations

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Repo — интерфейс для хранения и обновления Operations.
// Каждый сервис создает таблицу operations через migration (см.
// migrations/common/0001_operations.sql + 0002_operations_principal.sql).
type Repo interface {
	// Create сохраняет новую операцию (done=false). Principal записывается
	// как SystemPrincipal — backward-compat shim. Use-case с auth-ctx должен
	// вызывать CreateWithPrincipal (или передавать op.Principal заранее).
	Create(ctx context.Context, op Operation) error
	// CreateWithPrincipal сохраняет новую операцию с явно переданным
	// principal'ом. Вызывается из use-case'ов сервисов после
	// PrincipalFromContext(ctx).
	CreateWithPrincipal(ctx context.Context, op Operation, p Principal) error
	// Get возвращает операцию по ID. Возвращает ErrNotFound если операции нет.
	Get(ctx context.Context, id string) (*Operation, error)
	// List возвращает список операций с постраничной навигацией.
	List(ctx context.Context, filter ListFilter) ([]Operation, string, error)
	// MarkDone переводит операцию в done=true, записывает финальный ресурс (response).
	MarkDone(ctx context.Context, id string, response *anypb.Any) error
	// MarkError переводит операцию в done=true, записывает ошибку (google.rpc.Status).
	MarkError(ctx context.Context, id string, err *status.Status) error
	// Cancel переводит операцию в done=true со статусом CANCELLED.
	Cancel(ctx context.Context, id string) error
}

// ListFilter — параметры фильтрации/пагинации для List.
type ListFilter struct {
	ResourceID string // если непуст — фильтр по resource_id (денормализованное поле)
	AccountID  string // если непуст — фильтр по account_id (денормализованное поле, partial cursor-индекс)
	PageSize   int64
	PageToken  string
}

// ErrNotFound возвращается из Get, если операция не найдена.
var ErrNotFound = errors.New("operation not found")

// opColumns — канонический порядок колонок для scanOperation. Используется во
// всех SELECT/RETURNING, читающих полную строку операции (Get/List/GetOwned/
// CancelOwned/reconciler-claim) — единый источник истины порядка.
const opColumns = `id, description, created_at, created_by, modified_at, done,
	metadata_type, metadata_data,
	error_code, error_message, error_details,
	response_type, response_data,
	principal_type, principal_id, principal_display_name`

// rowQuerier — общий для *pgxpool.Pool и pgx.Tx интерфейс QueryRow, чтобы
// CAS-хелперы терминальной записи работали и на пуле (worker), и внутри
// транзакции reconciler'а (под FOR UPDATE-claim'ом).
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// markDoneCAS — идемпотентная терминальная запись success: CAS-on-`done`
// (UPDATE … WHERE id=$1 AND done=false) + различение already-done vs missing в
// одном round-trip'е через data-modifying CTE. updated=1 → nil; иначе строка
// присутствует → ErrAlreadyDone (уже терминальна, не перезаписываем); строки
// нет → ErrNotFound.
func markDoneCAS(ctx context.Context, q rowQuerier, table, id string, response *anypb.Any) error {
	respType, respData, err := marshalAny(response)
	if err != nil {
		return fmt.Errorf("repo.MarkDone: marshal response: %w", err)
	}
	sql := fmt.Sprintf(`
		WITH upd AS (
			UPDATE %s
			   SET done = true, modified_at = $2, response_type = $3, response_data = $4
			 WHERE id = $1 AND done = false
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM upd) AS updated,
		       EXISTS(SELECT 1 FROM %s WHERE id = $1) AS present`,
		table, table)
	var updated int
	var present bool
	if err := q.QueryRow(ctx, sql, id, time.Now().UTC(), respType, respData).Scan(&updated, &present); err != nil {
		return fmt.Errorf("repo.MarkDone: %w", err)
	}
	if updated == 1 {
		return nil
	}
	if present {
		return ErrAlreadyDone
	}
	return ErrNotFound
}

// markErrorCAS — симметрия markDoneCAS для терминальной записи ошибки.
func markErrorCAS(ctx context.Context, q rowQuerier, table, id string, errStatus *status.Status) error {
	errCode, errMsg, errDetails := marshalStatus(errStatus)
	sql := fmt.Sprintf(`
		WITH upd AS (
			UPDATE %s
			   SET done = true, modified_at = $2,
			       error_code = $3, error_message = $4, error_details = $5
			 WHERE id = $1 AND done = false
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM upd) AS updated,
		       EXISTS(SELECT 1 FROM %s WHERE id = $1) AS present`,
		table, table)
	var updated int
	var present bool
	if err := q.QueryRow(ctx, sql, id, time.Now().UTC(), errCode, errMsg, errDetails).Scan(&updated, &present); err != nil {
		return fmt.Errorf("repo.MarkError: %w", err)
	}
	if updated == 1 {
		return nil
	}
	if present {
		return ErrAlreadyDone
	}
	return ErrNotFound
}

// marshalStatus раскладывает google.rpc.Status в (error_code, error_message,
// error_details) для хранения в колонках. details сериализуются как
// proto.Marshal(Status) (восстанавливаются в scanOperation).
func marshalStatus(errStatus *status.Status) (*int32, *string, []byte) {
	if errStatus == nil {
		return nil, nil, nil
	}
	code := errStatus.GetCode()
	msg := errStatus.GetMessage()
	var details []byte
	if len(errStatus.GetDetails()) > 0 {
		if b, marshalErr := proto.Marshal(errStatus); marshalErr == nil {
			details = b
		}
	}
	return &code, &msg, details
}

// ownerPredicateSQL — ownership-предикат для GetOwned/CancelOwned: match по паре
// (principal_type, principal_id) ЛИБО по account_id там, где он NOT NULL и
// owner.AccountID непуст (IAM-ветка; для vpc/compute/nlb AccountID="" → инертна).
func ownerPredicateSQL(ptIdx, pidIdx, aidIdx int) string {
	return fmt.Sprintf(
		"((principal_type = $%d AND principal_id = $%d) OR ($%d <> '' AND account_id IS NOT NULL AND account_id = $%d))",
		ptIdx, pidIdx, aidIdx, aidIdx)
}

var _ OwnedOperationRepo = (*pgRepo)(nil)

// pgRepo — реализация Repo поверх pgxpool.
type pgRepo struct {
	pool   *pgxpool.Pool
	schema string // schema name (например "public" или "kacho_compute")
}

// NewRepo создает Repo для указанного пула и схемы.
// schema используется как квалификатор таблицы (schema.operations).
// Для схемы "public" передавайте "public".
func NewRepo(pool *pgxpool.Pool, schema string) Repo {
	return &pgRepo{pool: pool, schema: schema}
}

// tableName возвращает полное имя таблицы с квалификатором схемы.
func (r *pgRepo) tableName() string {
	return pgx.Identifier{r.schema, "operations"}.Sanitize()
}

// Create вставляет операцию в таблицу. Принципал по умолчанию —
// SystemPrincipal (backward-compat shim для сервисов, еще не пробросивших
// auth-ctx до repo). Use-case с auth-ctx должен использовать
// CreateWithPrincipal либо предварительно заполнить op.Principal и вызывать
// CreateWithPrincipal(ctx, op, op.Principal).
func (r *pgRepo) Create(ctx context.Context, op Operation) error {
	// Источник Principal в порядке приоритета:
	//   1. op.Principal — явно set'нут через NewFromContext / CreateWithPrincipal.
	//   2. PrincipalFromContext(ctx) — реальный Principal от UnaryPrincipalExtract.
	//   3. SystemPrincipal() — fallback (системные операции, бутстрап, миграции).
	//
	// Fallback на ctx делает Principal-propagation работающим без массовой замены
	// operations.New → operations.NewFromContext во всех use-case'ах: даже когда
	// use-case зовет operations.New(...) и op.Principal=zero, реальный
	// x-kacho-principal-* MD, извлеченный сервером в ctx через
	// grpcsrv.UnaryPrincipalExtract, подхватывается отсюда (иначе строка писалась бы
	// с principalType="system"/created_by="anonymous").
	p := op.Principal
	fromCtx := false
	if p == (Principal{}) {
		// ctxPrincipalFromContext возвращает Principal{} только если в ctx
		// был явный WithPrincipal — иначе SystemPrincipal-fallback. Проверяем
		// по type: "system" значит fallback (ctx без auth-interceptor'а),
		// любой другой type — реальный extract'ed Principal.
		ctxP := PrincipalFromContext(ctx)
		if ctxP.Type != "" && ctxP.Type != "system" {
			p = ctxP
			fromCtx = true
		} else {
			p = SystemPrincipal()
		}
	}
	// Sync CreatedBy с реальным principal.ID (legacy column для
	// backward-compat read'ов). Только если Principal пришел из ctx
	// (не system-fallback) — иначе оставляем "anonymous" как было.
	if fromCtx && op.CreatedBy == "anonymous" && p.ID != "" {
		op.CreatedBy = p.ID
	}
	return r.CreateWithPrincipal(ctx, op, p)
}

// CreateWithPrincipal вставляет операцию с явно переданным principal'ом.
// Если каноничный путь use-case'а — PrincipalFromContext(ctx) → этот метод.
func (r *pgRepo) CreateWithPrincipal(ctx context.Context, op Operation, p Principal) error {
	metaType, metaData, err := marshalAny(op.Metadata)
	if err != nil {
		return fmt.Errorf("repo.Create: marshal metadata: %w", err)
	}

	// Извлекаем resource_id из метаданных (денормализованный индекс для фильтрации).
	resourceID := extractResourceID(op.Metadata)
	// Извлекаем account_id по ТОЧНОМУ имени поля — additive
	// денормализация для account-scoped IAM operation-listing. Метаданные без
	// account_id (не-IAM / категория II) → "" → SQL NULL (back-compat).
	accountID := extractAccountID(op.Metadata)

	// Fallback на SystemPrincipal если передан пустой p (defensive).
	if p == (Principal{}) {
		p = SystemPrincipal()
	}

	q := fmt.Sprintf(`
		INSERT INTO %s
		  (id, description, created_at, created_by, modified_at, done,
		   metadata_type, metadata_data, resource_id, account_id,
		   principal_type, principal_id, principal_display_name)
		VALUES
		  ($1, $2, $3, $4, $5, false, $6, $7, $8, $9, $10, $11, $12)`,
		r.tableName(),
	)

	createdBy := op.CreatedBy
	if createdBy == "" {
		createdBy = "anonymous"
	}

	_, err = r.pool.Exec(ctx, q,
		op.ID,
		op.Description,
		op.CreatedAt,
		createdBy,
		op.ModifiedAt,
		metaType,
		metaData,
		nullableString(resourceID),
		nullableString(accountID),
		p.Type,
		p.ID,
		p.DisplayName,
	)
	if err != nil {
		return fmt.Errorf("repo.Create: %w", err)
	}
	return nil
}

// Get возвращает операцию по id.
func (r *pgRepo) Get(ctx context.Context, id string) (*Operation, error) {
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE id = $1`, opColumns, r.tableName())

	row := r.pool.QueryRow(ctx, q, id)
	op, err := scanOperation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repo.Get: %w", err)
	}
	return op, nil
}

// List возвращает список операций с фильтром и пагинацией по created_at/id курсору.
func (r *pgRepo) List(ctx context.Context, filter ListFilter) ([]Operation, string, error) {
	pageSize := filter.PageSize
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 50
	}

	args := []any{}
	conditions := []string{}
	argIdx := 1

	if filter.ResourceID != "" {
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argIdx))
		args = append(args, filter.ResourceID)
		argIdx++
	}

	if filter.AccountID != "" {
		// account-scoped IAM operation-listing. Использует
		// partial cursor-индекс operations_account_id_idx (account_id NOT NULL).
		conditions = append(conditions, fmt.Sprintf("account_id = $%d", argIdx))
		args = append(args, filter.AccountID)
		argIdx++
	}

	// page_token кодирует "created_at:id" последней записи предыдущей страницы.
	if filter.PageToken != "" {
		cursorCreatedAt, cursorID, err := decodePageToken(filter.PageToken)
		if err != nil {
			return nil, "", fmt.Errorf("repo.List: invalid page_token: %w", err)
		}
		conditions = append(conditions, fmt.Sprintf(
			"(created_at, id) > ($%d, $%d)", argIdx, argIdx+1,
		))
		args = append(args, cursorCreatedAt, cursorID)
		argIdx += 2
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	q := fmt.Sprintf(`
		SELECT %s
		FROM %s
		%s
		ORDER BY created_at ASC, id ASC
		LIMIT $%d`,
		opColumns, r.tableName(), where, argIdx,
	)
	args = append(args, pageSize+1) // запрашиваем на 1 больше для определения наличия следующей страницы

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("repo.List: %w", err)
	}
	defer rows.Close()

	var ops []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, "", fmt.Errorf("repo.List: scan: %w", err)
		}
		ops = append(ops, *op)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("repo.List: rows: %w", err)
	}

	var nextToken string
	if int64(len(ops)) > pageSize {
		last := ops[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, last.ID)
		ops = ops[:pageSize]
	}

	return ops, nextToken, nil
}

// MarkDone переводит операцию в done=true с финальным ресурсом. Идемпотентна и
// durable: CAS-on-`done` не перезатирает уже-терминальную строку (см. markDoneCAS).
func (r *pgRepo) MarkDone(ctx context.Context, id string, response *anypb.Any) error {
	return markDoneCAS(ctx, r.pool, r.tableName(), id, response)
}

// MarkError переводит операцию в done=true с ошибкой. Симметрично MarkDone:
// CAS-on-`done`, no-overwrite (markErrorCAS).
func (r *pgRepo) MarkError(ctx context.Context, id string, errStatus *status.Status) error {
	return markErrorCAS(ctx, r.pool, r.tableName(), id, errStatus)
}

// ErrAlreadyDone возвращается из терминальных переходов, если строка уже
// завершена (CAS-on-`done` не совпал). Маппится в FAILED_PRECONDITION на
// Cancel-пути; на worker-пути трактуется как идемпотентный no-op.
var ErrAlreadyDone = errors.New("operation already completed")

// Cancel переводит операцию в done=true со статусом CANCELLED (gRPC code 1).
// CAS-on-`done`: при 0 строках различает уже-завершенную (ErrAlreadyDone,
// FAILED_PRECONDITION) и несуществующую (ErrNotFound). Параллельный worker-
// MarkDone после commit'а Cancel попадает на тот же CAS → 0 строк → no-op,
// CANCELLED не затирается.
func (r *pgRepo) Cancel(ctx context.Context, id string) error {
	q := fmt.Sprintf(`
		UPDATE %s
		   SET done = true, modified_at = $2, error_code = 1, error_message = 'operation cancelled'
		 WHERE id = $1 AND done = false`,
		r.tableName(),
	)
	tag, err := r.pool.Exec(ctx, q, id, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("repo.Cancel: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// 0 rows: либо запись не существует, либо done=true. Различим через Get.
	op, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr // ErrNotFound или другое
	}
	if op.Done {
		return ErrAlreadyDone
	}
	return ErrNotFound
}

// GetOwned возвращает операцию ТОЛЬКО если она принадлежит owner. Ownership-
// предикат — внутри SQL WHERE (within-service инвариант на DB-уровне). 0 строк
// (нет такой ИЛИ не владелец) → ErrNotFound (no-leak, неотличимо).
func (r *pgRepo) GetOwned(ctx context.Context, id string, owner Owner) (*Operation, error) {
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE id = $1 AND %s`,
		opColumns, r.tableName(), ownerPredicateSQL(2, 3, 4))
	row := r.pool.QueryRow(ctx, q, id, owner.PrincipalType, owner.PrincipalID, owner.AccountID)
	op, err := scanOperation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repo.GetOwned: %w", err)
	}
	return op, nil
}

// CancelOwned — атомарная ownership-scoped отмена. Ownership-предикат и CAS-on-
// `done` в ОДНОМ UPDATE … WHERE … RETURNING (terminal-state читается тем же
// стейтментом, reload-Get не нужен; TOCTOU/second-writer-wins исключен).
// Идемпотентна на уже-CANCELLED (→ OK с тем же Operation); на терминале
// SUCCESS/ERROR → ErrAlreadyDone; чужая/нет → ErrNotFound.
func (r *pgRepo) CancelOwned(ctx context.Context, id string, owner Owner) (*Operation, error) {
	q := fmt.Sprintf(`
		UPDATE %s
		   SET done = true, modified_at = $2, error_code = 1, error_message = 'operation cancelled'
		 WHERE id = $1 AND done = false AND %s
		RETURNING %s`,
		r.tableName(), ownerPredicateSQL(3, 4, 5), opColumns)
	row := r.pool.QueryRow(ctx, q, id, time.Now().UTC(), owner.PrincipalType, owner.PrincipalID, owner.AccountID)
	op, err := scanOperation(row)
	if err == nil {
		return op, nil // отмена применена (CANCELLED)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("repo.CancelOwned: %w", err)
	}
	// 0 строк: классифицируем по ownership-scoped чтению (тот же предикат).
	existing, gErr := r.GetOwned(ctx, id, owner)
	if gErr != nil {
		return nil, gErr // ErrNotFound (нет / не владелец) или INTERNAL
	}
	if existing.Done {
		if existing.Error != nil && existing.Error.GetCode() == 1 {
			return existing, nil // идемпотентно: уже CANCELLED
		}
		return nil, ErrAlreadyDone // terminal SUCCESS/ERROR — нельзя отменить
	}
	// owned & done=false, но CAS не совпал — редкая гонка; fail-closed.
	return nil, ErrNotFound
}

// ---- helpers ----

// scanOperation читает одну строку из курсора (pgx.Row или pgx.Rows).
func scanOperation(row interface {
	Scan(dest ...any) error
}) (*Operation, error) {
	var op Operation
	var metaType, metaData *[]byte
	var metaTypeStr *string
	var errCode *int32
	var errMsg *string
	var errDetails *[]byte
	var respType *string
	var respData *[]byte
	var principalType, principalID, principalDisplay string

	err := row.Scan(
		&op.ID,
		&op.Description,
		&op.CreatedAt,
		&op.CreatedBy,
		&op.ModifiedAt,
		&op.Done,
		&metaTypeStr,
		&metaData,
		&errCode,
		&errMsg,
		&errDetails,
		&respType,
		&respData,
		&principalType,
		&principalID,
		&principalDisplay,
	)
	if err != nil {
		return nil, err
	}
	_ = metaType

	op.Principal = Principal{
		Type:        principalType,
		ID:          principalID,
		DisplayName: principalDisplay,
	}

	// восстанавливаем Metadata
	if metaTypeStr != nil && metaData != nil {
		op.Metadata = &anypb.Any{
			TypeUrl: *metaTypeStr,
			Value:   *metaData,
		}
	}

	// восстанавливаем Error
	if errCode != nil {
		op.Error = &status.Status{
			Code:    *errCode,
			Message: stringOrEmpty(errMsg),
		}
		if errDetails != nil {
			// десериализуем Details из сохраненного proto.Marshal(Status)
			var fullStatus status.Status
			if unmarshalErr := proto.Unmarshal(*errDetails, &fullStatus); unmarshalErr == nil {
				op.Error.Details = fullStatus.GetDetails()
			}
		}
	}

	// восстанавливаем Response
	if respType != nil && respData != nil {
		op.Response = &anypb.Any{
			TypeUrl: *respType,
			Value:   *respData,
		}
	}

	// Восстанавливаем Principal из колонок БД: иначе Repo.Get(id).Principal был бы
	// zero-value, а handler operationToProto возвращал бы пустые principal_* поля
	// даже при правильно записанной DB-строке.
	op.Principal = Principal{
		Type:        principalType,
		ID:          principalID,
		DisplayName: principalDisplay,
	}

	return &op, nil
}

// marshalAny сериализует *anypb.Any в (type_url, value) для хранения в БД.
func marshalAny(a *anypb.Any) (*string, []byte, error) {
	if a == nil {
		return nil, nil, nil
	}
	t := a.GetTypeUrl()
	return &t, a.GetValue(), nil
}

// extractResourceID пытается извлечь поле resource_id из метаданных операции.
// Конвенция: в metadata-сообщениях поле с именем, заканчивающимся на _id,
// содержит id связанного ресурса. Это поле сохраняется в денормализованное
// поле resource_id для эффективного фильтра по ресурсу в List.
// Поддерживается только через рефлексию protobuf.
func extractResourceID(metadata *anypb.Any) string {
	if metadata == nil {
		return ""
	}
	msg, err := metadata.UnmarshalNew()
	if err != nil {
		return ""
	}
	// Ищем поле с суффиксом _id в proto reflection
	fields := msg.ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := string(fd.Name())
		if strings.HasSuffix(name, "_id") {
			val := msg.ProtoReflect().Get(fd)
			if val.IsValid() {
				return val.String()
			}
		}
	}
	return ""
}

// extractAccountID извлекает поле с именем РОВНО account_id из метаданных
// операции для денормализации в account_id-колонку.
//
// В отличие от extractResourceID (первое поле с суффиксом _id), это чтение
// СТРОГО по точному имени account_id: иначе suffix-loop вернул бы первое _id
// (project_id / user_id / service_account_id), а не owning account. account_id —
// non-first поле в IAM *Metadata-сообщениях категории (I), поэтому
// extractResourceID и extractAccountID не конфликтуют (resource_id остается
// первым _id-полем). Метаданные без account_id (vpc/compute/nlb/apps и
// IAM-категория (II)) → "" → SQL NULL (additive/back-compat).
func extractAccountID(metadata *anypb.Any) string {
	if metadata == nil {
		return ""
	}
	msg, err := metadata.UnmarshalNew()
	if err != nil {
		return ""
	}
	fd := msg.ProtoReflect().Descriptor().Fields().ByName("account_id")
	if fd == nil {
		return ""
	}
	val := msg.ProtoReflect().Get(fd)
	if !val.IsValid() {
		return ""
	}
	return val.String()
}

// nullableString возвращает *string или nil если строка пустая.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// stringOrEmpty разыменовывает *string или возвращает "".
func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// encodePageToken кодирует created_at + id в непрозрачный page_token.
func encodePageToken(createdAt time.Time, id string) string {
	raw := strconv.FormatInt(createdAt.UnixNano(), 10) + ":" + id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodePageToken декодирует page_token обратно в (created_at, id).
func decodePageToken(token string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(b), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, "", errors.New("malformed token")
	}
	ns, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, "", err
	}
	return time.Unix(0, ns).UTC(), parts[1], nil
}
