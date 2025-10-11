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

// RoleRepository implements role persistence operations.
type RoleRepository struct {
	pool    *pgxpool.Pool
	builder squirrel.StatementBuilderType
}

// NewRoleRepository constructs a PostgreSQL-backed role repository.
func NewRoleRepository(pool *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{
		pool:    pool,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
}

// Create inserts a new role.
func (r *RoleRepository) Create(ctx context.Context, role domain.Role) error {
	stmt, args, err := r.builder.Insert("iam.roles").
		Columns("id", "name", "description").
		Values(role.ID, role.Name, role.Description).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert role sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("insert role: %w", err)
	}

	return nil
}

// List retrieves all roles sorted by name.
func (r *RoleRepository) List(ctx context.Context) ([]domain.Role, error) {
	stmt, args, err := r.builder.Select("id", "name", "description").
		From("iam.roles").
		OrderBy("name ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list roles sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query roles: %w", err)
	}
	defer rows.Close()

	var roles []domain.Role

	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}

	return roles, nil
}

// GetByName retrieves a role by its unique name.
func (r *RoleRepository) GetByName(ctx context.Context, name string) (*domain.Role, error) {
	stmt, args, err := r.builder.Select("id", "name", "description").
		From("iam.roles").
		Where(squirrel.Eq{"name": name}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select role by name sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var (
		role        domain.Role
		description sql.NullString
	)

	if err := row.Scan(&role.ID, &role.Name, &description); err != nil {
		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan role by name: %w", err)
	}

	if description.Valid {
		role.Description = &description.String
	}

	return &role, nil
}

// AttachPermissions links the provided permissions to the role.
func (r *RoleRepository) AttachPermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	if len(permissionIDs) == 0 {
		return nil
	}

	query := r.builder.Insert("iam.role_permissions").
		Columns("role_id", "permission_id")

	for _, permissionID := range permissionIDs {
		query = query.Values(roleID, permissionID)
	}

	stmt, args, err := query.Suffix("ON CONFLICT DO NOTHING").ToSql()
	if err != nil {
		return fmt.Errorf("build attach role permissions sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("attach role permissions: %w", err)
	}

	return nil
}

// AssignToUsers assigns the role to the provided user IDs.
func (r *RoleRepository) AssignToUsers(ctx context.Context, roleID string, userIDs []string) error {
	if len(userIDs) == 0 {
		return nil
	}

	assignedAt := time.Now().UTC()
	query := r.builder.Insert("iam.user_roles").
		Columns("user_id", "role_id", "assigned_at")

	for _, userID := range userIDs {
		query = query.Values(userID, roleID, assignedAt)
	}

	stmt, args, err := query.Suffix("ON CONFLICT DO NOTHING").ToSql()
	if err != nil {
		return fmt.Errorf("build assign role to users sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("assign role to users: %w", err)
	}

	return nil
}

// ListByUser returns roles assigned to the specified user.
func (r *RoleRepository) ListByUser(ctx context.Context, userID string) ([]domain.Role, error) {
	stmt, args, err := r.builder.Select("r.id", "r.name", "r.description").
		From("iam.roles r").
		Join("iam.user_roles ur ON ur.role_id = r.id").
		Where(squirrel.Eq{"ur.user_id": userID}).
		OrderBy("r.name ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build roles by user sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query roles by user: %w", err)
	}
	defer rows.Close()

	roles := make([]domain.Role, 0)
	for rows.Next() {
		var (
			role        domain.Role
			description sql.NullString
		)
		if err := rows.Scan(&role.ID, &role.Name, &description); err != nil {
			return nil, fmt.Errorf("scan role by user: %w", err)
		}
		if description.Valid {
			role.Description = &description.String
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles by user: %w", err)
	}

	return roles, nil
}

var _ port.RoleRepository = (*RoleRepository)(nil)
