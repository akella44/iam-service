package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	squirrel "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// SubjectVersionRepository persists subject version records in PostgreSQL.
type SubjectVersionRepository struct {
	pool    *pgxpool.Pool
	exec    pgExecutor
	builder squirrel.StatementBuilderType
}

// NewSubjectVersionRepository constructs the repository from a generic executor.
func NewSubjectVersionRepository(exec pgExecutor) *SubjectVersionRepository {
	repo := &SubjectVersionRepository{
		exec:    exec,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
	if pool, ok := exec.(*pgxpool.Pool); ok {
		repo.pool = pool
	}
	return repo
}

// WithTx binds the repository to execute statements within the supplied transaction.
func (r *SubjectVersionRepository) WithTx(tx pgx.Tx) *SubjectVersionRepository {
	if tx == nil {
		return r
	}
	return &SubjectVersionRepository{
		pool:    r.pool,
		exec:    tx,
		builder: r.builder,
	}
}

var _ port.SubjectVersionRepository = (*SubjectVersionRepository)(nil)

// Get retrieves the current subject version state.
func (r *SubjectVersionRepository) Get(ctx context.Context, subjectID string) (*domain.SubjectVersion, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, fmt.Errorf("subject id is required")
	}

	stmt, args, err := r.builder.
		Select(
			"subject_id",
			"current_version",
			"not_before",
			"updated_at",
			"updated_by",
			"reason",
		).
		From("iam.subject_versions").
		Where(squirrel.Eq{"subject_id": subjectID}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select subject version sql: %w", err)
	}

	row := r.exec.QueryRow(ctx, stmt, args...)

	var (
		notBefore sql.NullTime
		reason    sql.NullString
		subject   domain.SubjectVersion
	)

	if err := row.Scan(&subject.SubjectID, &subject.CurrentVersion, &notBefore, &subject.UpdatedAt, &subject.UpdatedBy, &reason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan subject version: %w", err)
	}

	if notBefore.Valid {
		nb := notBefore.Time
		subject.NotBefore = &nb
	}
	if reason.Valid {
		value := reason.String
		subject.Reason = &value
	}

	return &subject, nil
}

// ApplyMutation upserts the subject version row ensuring monotonically increasing version counters.
func (r *SubjectVersionRepository) ApplyMutation(ctx context.Context, mutation domain.SubjectVersionMutation) (domain.SubjectVersionChange, error) {
	var change domain.SubjectVersionChange

	subjectID := strings.TrimSpace(mutation.SubjectID)
	if subjectID == "" {
		return change, fmt.Errorf("subject id is required")
	}
	actor := strings.TrimSpace(mutation.Actor)
	if actor == "" {
		return change, fmt.Errorf("actor is required")
	}

	appliedAt := mutation.AppliedAt
	if appliedAt.IsZero() {
		appliedAt = time.Now().UTC()
	}

	var previous domain.SubjectVersion
	var notBefore sql.NullTime
	var reason sql.NullString

	stmt := `
        SELECT subject_id, current_version, not_before, updated_at, updated_by, reason
          FROM iam.subject_versions
         WHERE subject_id = $1
         FOR UPDATE
    `

	row := r.exec.QueryRow(ctx, stmt, subjectID)
	switch err := row.Scan(&previous.SubjectID, &previous.CurrentVersion, &notBefore, &previous.UpdatedAt, &previous.UpdatedBy, &reason); {
	case err == nil:
		if notBefore.Valid {
			nb := notBefore.Time
			previous.NotBefore = &nb
		}
		if reason.Valid {
			value := reason.String
			previous.Reason = &value
		}
		change.Previous = &previous
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, sql.ErrNoRows):
		previous = domain.SubjectVersion{SubjectID: subjectID, CurrentVersion: 0}
	default:
		return change, fmt.Errorf("select subject version: %w", err)
	}

	currentVersion := previous.CurrentVersion
	if currentVersion < 0 {
		currentVersion = 0
	}

	var newVersion int64
	if mutation.NewVersion != nil {
		newVersion = *mutation.NewVersion
		if newVersion <= 0 {
			return change, fmt.Errorf("new version must be positive")
		}
		if currentVersion > 0 && newVersion < currentVersion {
			return change, fmt.Errorf("version regression is not allowed (current=%d, incoming=%d)", currentVersion, newVersion)
		}
	} else {
		if currentVersion <= 0 {
			newVersion = 1
		} else {
			newVersion = currentVersion + 1
		}
	}

	var newNotBefore *time.Time
	if mutation.NotBefore != nil {
		if mutation.NotBefore.IsZero() {
			mutation.NotBefore = nil
		}
	}
	if mutation.NotBefore != nil {
		nb := mutation.NotBefore.UTC()
		newNotBefore = &nb
	}

	normalizedReason := strings.TrimSpace(mutation.Reason)
	var reasonValue *string
	if normalizedReason != "" {
		reasonValue = &normalizedReason
	}

	upsertStmt := `
        INSERT INTO iam.subject_versions (subject_id, current_version, not_before, updated_at, updated_by, reason)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (subject_id) DO UPDATE
            SET current_version = EXCLUDED.current_version,
                not_before = EXCLUDED.not_before,
                updated_at = EXCLUDED.updated_at,
                updated_by = EXCLUDED.updated_by,
                reason = EXCLUDED.reason
        RETURNING subject_id, current_version, not_before, updated_at, updated_by, reason
    `

	var (
		inserted    domain.SubjectVersion
		insertedNB  sql.NullTime
		insertedRsn sql.NullString
	)

	row = r.exec.QueryRow(ctx, upsertStmt, subjectID, newVersion, optionalTime(newNotBefore), appliedAt, actor, optionalString(reasonValue))
	if err := row.Scan(&inserted.SubjectID, &inserted.CurrentVersion, &insertedNB, &inserted.UpdatedAt, &inserted.UpdatedBy, &insertedRsn); err != nil {
		return change, fmt.Errorf("upsert subject version: %w", err)
	}

	if insertedNB.Valid {
		nb := insertedNB.Time
		inserted.NotBefore = &nb
	}
	if insertedRsn.Valid {
		value := insertedRsn.String
		inserted.Reason = &value
	}

	change.Current = inserted
	return change, nil
}

// AppendAudit stores a subject version audit record.
func (r *SubjectVersionRepository) AppendAudit(ctx context.Context, entry domain.SubjectVersionAuditEntry) error {
	subjectID := strings.TrimSpace(entry.SubjectID)
	if subjectID == "" {
		return fmt.Errorf("subject id is required")
	}
	actor := strings.TrimSpace(entry.Actor)
	if actor == "" {
		return fmt.Errorf("actor is required")
	}
	createdAt := entry.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	trimmedReason := strings.TrimSpace(entry.Reason)
	var reasonPtr *string
	if trimmedReason != "" {
		reasonPtr = &trimmedReason
	}

	stmt, args, err := r.builder.Insert("iam.subject_version_audit").
		Columns(
			"event_id",
			"subject_id",
			"previous_version",
			"new_version",
			"previous_not_before",
			"new_not_before",
			"actor",
			"reason",
			"created_at",
		).
		Values(
			entry.EventID,
			subjectID,
			optionalInt64(entry.PreviousVersion),
			entry.NewVersion,
			optionalTime(entry.PreviousNotBefore),
			optionalTime(entry.NewNotBefore),
			actor,
			optionalString(reasonPtr),
			createdAt,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert subject version audit sql: %w", err)
	}

	if _, err := r.exec.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("insert subject version audit: %w", err)
	}

	return nil
}

func optionalInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
