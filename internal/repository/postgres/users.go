package postgres

import (
	"context"
	"database/sql"
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

// UserRepository implements port.UserRepository using PostgreSQL.
type UserRepository struct {
	pool    *pgxpool.Pool
	builder squirrel.StatementBuilderType
}

// NewUserRepository wires a PostgreSQL-backed user repository.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		pool:    pool,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
}

// Create inserts a new user row.
func (r *UserRepository) Create(ctx context.Context, user domain.User) error {
	var emailValue any
	if user.Email != "" {
		emailValue = user.Email
	}

	var phoneValue any
	if user.Phone != nil && *user.Phone != "" {
		phoneValue = *user.Phone
	}

	query := r.builder.Insert("iam.users").
		Columns(
			"id",
			"username",
			"email",
			"phone",
			"password_hash",
			"password_algo",
			"status",
			"is_active",
			"registered_at",
			"last_login",
			"last_password_change",
		).
		Values(
			user.ID,
			user.Username,
			emailValue,
			phoneValue,
			user.PasswordHash,
			user.PasswordAlgo,
			user.Status,
			user.IsActive,
			user.RegisteredAt,
			user.LastLogin,
			user.LastPasswordChange,
		)

	sql, args, err := query.ToSql()
	if err != nil {
		return fmt.Errorf("build insert user sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by identifier.
func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	stmt, args, err := r.builder.
		Select(
			"id",
			"username",
			"email",
			"phone",
			"password_hash",
			"password_algo",
			"status",
			"is_active",
			"registered_at",
			"last_login",
			"last_password_change",
		).
		From("iam.users").
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select user sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var (
		lastLogin *time.Time
		email     sql.NullString
		phone     sql.NullString
		user      domain.User
	)

	if err := row.Scan(
		&user.ID,
		&user.Username,
		&email,
		&phone,
		&user.PasswordHash,
		&user.PasswordAlgo,
		&user.Status,
		&user.IsActive,
		&user.RegisteredAt,
		&lastLogin,
		&user.LastPasswordChange,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}

	user.LastLogin = lastLogin
	if email.Valid {
		user.Email = email.String
	} else {
		user.Email = ""
	}
	if phone.Valid {
		val := phone.String
		user.Phone = &val
	} else {
		user.Phone = nil
	}

	return &user, nil
}

// GetByIdentifier retrieves a user by username, email, or phone identifier.
func (r *UserRepository) GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error) {
	stmt, args, err := r.builder.
		Select(
			"id",
			"username",
			"email",
			"phone",
			"password_hash",
			"password_algo",
			"status",
			"is_active",
			"registered_at",
			"last_login",
			"last_password_change",
		).
		From("iam.users").
		Where(squirrel.Or{
			squirrel.Eq{"username": identifier},
			squirrel.Eq{"email": identifier},
			squirrel.Eq{"phone": identifier},
		}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select user by identifier sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var (
		lastLogin *time.Time
		email     sql.NullString
		phone     sql.NullString
		user      domain.User
	)

	if err := row.Scan(
		&user.ID,
		&user.Username,
		&email,
		&phone,
		&user.PasswordHash,
		&user.PasswordAlgo,
		&user.Status,
		&user.IsActive,
		&user.RegisteredAt,
		&lastLogin,
		&user.LastPasswordChange,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan user by identifier: %w", err)
	}

	user.LastLogin = lastLogin
	if email.Valid {
		user.Email = email.String
	} else {
		user.Email = ""
	}
	if phone.Valid {
		val := phone.String
		user.Phone = &val
	} else {
		user.Phone = nil
	}

	return &user, nil
}

// UpdateStatus updates the status field for a user.
func (r *UserRepository) UpdateStatus(ctx context.Context, id string, status domain.UserStatus) error {
	stmt, args, err := r.builder.Update("iam.users").
		Set("status", status).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build update user status sql: %w", err)
	}

	ct, err := r.pool.Exec(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("update user status: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdatePassword updates a user's password hash, algorithm, and last change timestamp.
func (r *UserRepository) UpdatePassword(ctx context.Context, id string, passwordHash string, passwordAlgo string, changedAt time.Time) error {
	stmt, args, err := r.builder.Update("iam.users").
		Set("password_hash", passwordHash).
		Set("password_algo", passwordAlgo).
		Set("last_password_change", changedAt).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build update password sql: %w", err)
	}

	ct, err := r.pool.Exec(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// AssignRoles links the user to the provided set of role identifiers.
func (r *UserRepository) AssignRoles(ctx context.Context, userID string, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return nil
	}

	assignedAt := time.Now().UTC()
	query := r.builder.Insert("iam.user_roles").
		Columns("user_id", "role_id", "assigned_at")

	for _, roleID := range roleIDs {
		query = query.Values(userID, roleID, assignedAt)
	}

	stmt, args, err := query.Suffix("ON CONFLICT DO NOTHING").ToSql()
	if err != nil {
		return fmt.Errorf("build assign roles sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("assign roles: %w", err)
	}

	return nil
}

// RevokeRoles removes the specified role assignments from the user.
func (r *UserRepository) RevokeRoles(ctx context.Context, userID string, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return nil
	}

	stmt, args, err := r.builder.Delete("iam.user_roles").
		Where(squirrel.Eq{"user_id": userID}).
		Where(squirrel.Eq{"role_id": roleIDs}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build revoke roles sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("revoke roles: %w", err)
	}

	return nil
}

// GetUserRoles lists the role assignments for the provided user.
func (r *UserRepository) GetUserRoles(ctx context.Context, userID string) ([]domain.UserRole, error) {
	stmt, args, err := r.builder.Select("user_id", "role_id", "assigned_at").
		From("iam.user_roles").
		Where(squirrel.Eq{"user_id": userID}).
		OrderBy("assigned_at ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build get user roles sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query user roles: %w", err)
	}
	defer rows.Close()

	assignments := make([]domain.UserRole, 0)
	for rows.Next() {
		var assignment domain.UserRole
		if err := rows.Scan(&assignment.UserID, &assignment.RoleID, &assignment.AssignedAt); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		assignments = append(assignments, assignment)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user roles: %w", err)
	}

	return assignments, nil
}

// ListPasswordHistory retrieves the most recent password hashes for a user.
func (r *UserRepository) ListPasswordHistory(ctx context.Context, userID string, limit int) ([]domain.UserPasswordHistory, error) {
	trimmedID := strings.TrimSpace(userID)
	if trimmedID == "" {
		return nil, fmt.Errorf("user id is required")
	}

	builder := r.builder.Select("id", "user_id", "password_hash", "set_at").
		From("iam.user_password_history").
		Where(squirrel.Eq{"user_id": trimmedID}).
		OrderBy("set_at DESC")
	if limit > 0 {
		builder = builder.Limit(uint64(limit))
	}

	stmt, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select password history sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query password history: %w", err)
	}
	defer rows.Close()

	history := make([]domain.UserPasswordHistory, 0)
	for rows.Next() {
		var record domain.UserPasswordHistory
		if err := rows.Scan(&record.ID, &record.UserID, &record.PasswordHash, &record.SetAt); err != nil {
			return nil, fmt.Errorf("scan password history: %w", err)
		}
		history = append(history, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate password history: %w", err)
	}

	return history, nil
}

// AddPasswordHistory inserts a password hash into the history table.
func (r *UserRepository) AddPasswordHistory(ctx context.Context, entry domain.UserPasswordHistory) error {
	userID := strings.TrimSpace(entry.UserID)
	if userID == "" {
		return fmt.Errorf("user id is required")
	}
	if strings.TrimSpace(entry.PasswordHash) == "" {
		return fmt.Errorf("password hash is required")
	}

	setAt := entry.SetAt
	if setAt.IsZero() {
		setAt = time.Now().UTC()
	}

	builder := r.builder.Insert("iam.user_password_history")
	if entry.ID != "" {
		builder = builder.Columns("id", "user_id", "password_hash", "set_at").
			Values(entry.ID, userID, entry.PasswordHash, setAt)
	} else {
		builder = builder.Columns("user_id", "password_hash", "set_at").
			Values(userID, entry.PasswordHash, setAt)
	}

	stmt, args, err := builder.ToSql()
	if err != nil {
		return fmt.Errorf("build insert password history sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("insert password history: %w", err)
	}

	return nil
}

// TrimPasswordHistory ensures only the most recent maxEntries hashes are retained.
func (r *UserRepository) TrimPasswordHistory(ctx context.Context, userID string, maxEntries int) error {
	if maxEntries <= 0 {
		return nil
	}

	trimmedID := strings.TrimSpace(userID)
	if trimmedID == "" {
		return fmt.Errorf("user id is required")
	}

	stmt := `
		DELETE FROM iam.user_password_history
		 WHERE user_id = $1
		   AND id NOT IN (
				SELECT id
				  FROM iam.user_password_history
				 WHERE user_id = $1
				 ORDER BY set_at DESC
				 LIMIT $2
		   )
	`

	if _, err := r.pool.Exec(ctx, stmt, trimmedID, maxEntries); err != nil {
		return fmt.Errorf("trim password history: %w", err)
	}

	return nil
}

var _ port.UserRepository = (*UserRepository)(nil)
