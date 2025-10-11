package postgres

import "github.com/jackc/pgx/v5/pgxpool"

// Repositories groups concrete PostgreSQL repository implementations.
type Repositories struct {
	Users       *UserRepository
	Roles       *RoleRepository
	Permissions *PermissionRepository
	Tokens      *TokenRepository
	Sessions    *SessionRepository
}

// NewRepositories wires all repositories backed by the provided pool.
func NewRepositories(pool *pgxpool.Pool) *Repositories {
	return &Repositories{
		Users:       NewUserRepository(pool),
		Roles:       NewRoleRepository(pool),
		Permissions: NewPermissionRepository(pool),
		Tokens:      NewTokenRepository(pool),
		Sessions:    NewSessionRepository(pool),
	}
}
