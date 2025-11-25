package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repositories groups concrete PostgreSQL repository implementations.
type Repositories struct {
	pool            *pgxpool.Pool
	Users           *UserRepository
	Roles           *RoleRepository
	Permissions     *PermissionRepository
	Tokens          *TokenRepository
	Sessions        *SessionRepository
	SubjectVersions *SubjectVersionRepository
}

// NewRepositories wires all repositories backed by the provided pool.
func NewRepositories(pool *pgxpool.Pool) *Repositories {
	return &Repositories{
		pool:            pool,
		Users:           NewUserRepository(pool),
		Roles:           NewRoleRepository(pool),
		Permissions:     NewPermissionRepository(pool),
		Tokens:          NewTokenRepository(pool),
		Sessions:        NewSessionRepository(pool),
		SubjectVersions: NewSubjectVersionRepository(pool),
	}
}

// WithTx clones the repository set so that each repository issues statements within the supplied transaction.
func (r *Repositories) WithTx(tx pgx.Tx) *Repositories {
	if tx == nil {
		return r
	}

	clone := &Repositories{pool: r.pool}
	if r.Users != nil {
		clone.Users = r.Users.WithTx(tx)
	}
	if r.Roles != nil {
		clone.Roles = r.Roles.WithTx(tx)
	}
	if r.Permissions != nil {
		clone.Permissions = r.Permissions.WithTx(tx)
	}
	if r.Tokens != nil {
		clone.Tokens = r.Tokens.WithTx(tx)
	}
	if r.Sessions != nil {
		clone.Sessions = r.Sessions.WithTx(tx)
	}
	if r.SubjectVersions != nil {
		clone.SubjectVersions = r.SubjectVersions.WithTx(tx)
	}
	return clone
}

// WithinTransaction executes the provided function within a database transaction, committing on success or rolling back on failure.
func (r *Repositories) WithinTransaction(ctx context.Context, fn func(txRepos *Repositories) error) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("postgres pool not configured")
	}
	if fn == nil {
		return fmt.Errorf("transaction callback is required")
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	completed := false
	defer func() {
		if !completed {
			_ = tx.Rollback(ctx)
		}
	}()

	if err := fn(r.WithTx(tx)); err != nil {
		rollbackErr := tx.Rollback(ctx)
		completed = true
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return fmt.Errorf("rollback transaction: %v (original error: %w)", rollbackErr, err)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		completed = true
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return fmt.Errorf("commit transaction: %w (rollback failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("commit transaction: %w", err)
	}

	completed = true
	return nil
}
