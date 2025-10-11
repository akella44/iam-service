package postgres

import (
	"context"
	"database/sql"
	"fmt"
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

var _ port.UserRepository = (*UserRepository)(nil)
