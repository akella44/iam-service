package postgres

import (
	"context"
	"database/sql"
	"fmt"

	squirrel "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// PermissionRepository implements port.PermissionRepository over PostgreSQL.
type PermissionRepository struct {
	pool    *pgxpool.Pool
	builder squirrel.StatementBuilderType
}

// NewPermissionRepository constructs a permission repository instance.
func NewPermissionRepository(pool *pgxpool.Pool) *PermissionRepository {
	return &PermissionRepository{
		pool:    pool,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
}

// Create inserts a new permission row.
func (r *PermissionRepository) Create(ctx context.Context, permission domain.Permission) error {
	stmt, args, err := r.builder.Insert("iam.permissions").
		Columns("id", "name", "description").
		Values(permission.ID, permission.Name, permission.Description).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert permission sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("insert permission: %w", err)
	}

	return nil
}

// GetByName retrieves a permission by its unique name.
func (r *PermissionRepository) GetByName(ctx context.Context, name string) (*domain.Permission, error) {
	stmt, args, err := r.builder.Select("id", "name", "description").
		From("iam.permissions").
		Where(squirrel.Eq{"name": name}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select permission by name sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var (
		permission  domain.Permission
		description sql.NullString
	)

	if err := row.Scan(&permission.ID, &permission.Name, &description); err != nil {
		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan permission by name: %w", err)
	}

	if description.Valid {
		permission.Description = &description.String
	}

	return &permission, nil
}

// ListByRole returns permissions mapped to a role via role_permissions.
func (r *PermissionRepository) ListByRole(ctx context.Context, roleID string) ([]domain.Permission, error) {
	stmt, args, err := r.builder.Select("p.id", "p.name", "p.description").
		From("iam.permissions p").
		Join("iam.role_permissions rp ON rp.permission_id = p.id").
		Where(squirrel.Eq{"rp.role_id": roleID}).
		OrderBy("p.name ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build permissions by role sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query permissions: %w", err)
	}
	defer rows.Close()

	var permissions []domain.Permission
	for rows.Next() {
		var permission domain.Permission
		if err := rows.Scan(&permission.ID, &permission.Name, &permission.Description); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions: %w", err)
	}

	return permissions, nil
}

// ListByUser returns distinct permissions assigned to the user via roles.
func (r *PermissionRepository) ListByUser(ctx context.Context, userID string) ([]domain.Permission, error) {
	stmt, args, err := r.builder.Select("DISTINCT p.id", "p.name", "p.description").
		From("iam.permissions p").
		Join("iam.role_permissions rp ON rp.permission_id = p.id").
		Join("iam.user_roles ur ON ur.role_id = rp.role_id").
		Where(squirrel.Eq{"ur.user_id": userID}).
		OrderBy("p.name ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build permissions by user sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query permissions by user: %w", err)
	}
	defer rows.Close()

	var permissions []domain.Permission
	for rows.Next() {
		var permission domain.Permission
		if err := rows.Scan(&permission.ID, &permission.Name, &permission.Description); err != nil {
			return nil, fmt.Errorf("scan permission by user: %w", err)
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions by user: %w", err)
	}

	return permissions, nil
}

var _ port.PermissionRepository = (*PermissionRepository)(nil)
