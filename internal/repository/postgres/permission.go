package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

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
		Columns("id", "name", "service_namespace", "action", "description").
		Values(permission.ID, permission.Name, permission.ServiceNamespace, permission.Action, permission.Description).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert permission sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("insert permission: %w", err)
	}

	return nil
}

// GetByID retrieves a permission by its identifier.
func (r *PermissionRepository) GetByID(ctx context.Context, id string) (*domain.Permission, error) {
	stmt, args, err := r.builder.Select(
		"id",
		"name",
		"service_namespace",
		"action",
		"description",
	).
		From("iam.permissions").
		Where(squirrel.Eq{"id": id}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select permission by id sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	permission, err := scanPermissionRow(func(dest ...any) error { return row.Scan(dest...) })
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan permission by id: %w", err)
	}

	return permission, nil
}

// GetByName retrieves a permission by its unique canonical name.
func (r *PermissionRepository) GetByName(ctx context.Context, name string) (*domain.Permission, error) {
	stmt, args, err := r.builder.Select(
		"id",
		"name",
		"service_namespace",
		"action",
		"description",
	).
		From("iam.permissions").
		Where(squirrel.Eq{"name": name}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select permission by name sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	permission, err := scanPermissionRow(func(dest ...any) error { return row.Scan(dest...) })
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan permission by name: %w", err)
	}

	return permission, nil
}

// Update persists the supplied permission fields.
func (r *PermissionRepository) Update(ctx context.Context, permission domain.Permission) error {
	stmt, args, err := r.builder.Update("iam.permissions").
		Set("name", permission.Name).
		Set("service_namespace", permission.ServiceNamespace).
		Set("action", permission.Action).
		Set("description", permission.Description).
		Where(squirrel.Eq{"id": permission.ID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build update permission sql: %w", err)
	}

	res, err := r.pool.Exec(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("update permission: %w", err)
	}

	if res.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// Delete removes a permission by identifier.
func (r *PermissionRepository) Delete(ctx context.Context, id string) error {
	stmt, args, err := r.builder.Delete("iam.permissions").
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build delete permission sql: %w", err)
	}

	res, err := r.pool.Exec(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("delete permission: %w", err)
	}

	if res.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// List returns permissions with optional filtering and pagination.
func (r *PermissionRepository) List(ctx context.Context, filter port.PermissionFilter) ([]domain.Permission, error) {
	query := r.builder.Select(
		"id",
		"name",
		"service_namespace",
		"action",
		"description",
	).
		From("iam.permissions").
		OrderBy("service_namespace ASC", "action ASC")

	if namespace := strings.TrimSpace(filter.ServiceNamespace); namespace != "" {
		query = query.Where(squirrel.Eq{"service_namespace": namespace})
	}

	if filter.Limit > 0 {
		query = query.Limit(uint64(filter.Limit))
	}

	if filter.Offset > 0 {
		query = query.Offset(uint64(filter.Offset))
	}

	stmt, args, err := query.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list permissions sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]domain.Permission, 0)
	for rows.Next() {
		permission, err := scanPermissionRow(func(dest ...any) error { return rows.Scan(dest...) })
		if err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions = append(permissions, *permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions: %w", err)
	}

	return permissions, nil
}

// Count returns the total number of permissions matching the provided filter.
func (r *PermissionRepository) Count(ctx context.Context, filter port.PermissionFilter) (int, error) {
	query := r.builder.Select("COUNT(*)").
		From("iam.permissions")

	if namespace := strings.TrimSpace(filter.ServiceNamespace); namespace != "" {
		query = query.Where(squirrel.Eq{"service_namespace": namespace})
	}

	stmt, args, err := query.ToSql()
	if err != nil {
		return 0, fmt.Errorf("build count permissions sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("scan permissions count: %w", err)
	}

	return int(count), nil
}

// ListNamespaces aggregates permissions per service namespace for catalog views.
func (r *PermissionRepository) ListNamespaces(ctx context.Context) ([]port.PermissionNamespaceSummary, error) {
	stmt, args, err := r.builder.Select(
		"service_namespace",
		"COUNT(*)",
	).
		From("iam.permissions").
		GroupBy("service_namespace").
		OrderBy("service_namespace ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list namespaces sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query permission namespaces: %w", err)
	}
	defer rows.Close()

	summaries := make([]port.PermissionNamespaceSummary, 0)
	for rows.Next() {
		var summary port.PermissionNamespaceSummary
		if err := rows.Scan(&summary.ServiceNamespace, &summary.PermissionCount); err != nil {
			return nil, fmt.Errorf("scan permission namespace: %w", err)
		}
		summaries = append(summaries, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permission namespaces: %w", err)
	}

	return summaries, nil
}

// ListByRole returns permissions mapped to a role via role_permissions.
func (r *PermissionRepository) ListByRole(ctx context.Context, roleID string) ([]domain.Permission, error) {
	stmt, args, err := r.builder.Select(
		"p.id",
		"p.name",
		"p.service_namespace",
		"p.action",
		"p.description",
	).
		From("iam.permissions p").
		Join("iam.role_permissions rp ON rp.permission_id = p.id").
		Where(squirrel.Eq{"rp.role_id": roleID}).
		OrderBy("p.service_namespace ASC", "p.action ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build permissions by role sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query permissions by role: %w", err)
	}
	defer rows.Close()

	permissions := make([]domain.Permission, 0)
	for rows.Next() {
		permission, err := scanPermissionRow(func(dest ...any) error { return rows.Scan(dest...) })
		if err != nil {
			return nil, fmt.Errorf("scan permission by role: %w", err)
		}
		permissions = append(permissions, *permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions by role: %w", err)
	}

	return permissions, nil
}

// ListByUser returns distinct permissions assigned to the user via roles.
func (r *PermissionRepository) ListByUser(ctx context.Context, userID string) ([]domain.Permission, error) {
	stmt, args, err := r.builder.Select(
		"DISTINCT p.id",
		"p.name",
		"p.service_namespace",
		"p.action",
		"p.description",
	).
		From("iam.permissions p").
		Join("iam.role_permissions rp ON rp.permission_id = p.id").
		Join("iam.user_roles ur ON ur.role_id = rp.role_id").
		Where(squirrel.Eq{"ur.user_id": userID}).
		OrderBy("p.service_namespace ASC", "p.action ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build permissions by user sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query permissions by user: %w", err)
	}
	defer rows.Close()

	permissions := make([]domain.Permission, 0)
	for rows.Next() {
		permission, err := scanPermissionRow(func(dest ...any) error { return rows.Scan(dest...) })
		if err != nil {
			return nil, fmt.Errorf("scan permission by user: %w", err)
		}
		permissions = append(permissions, *permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions by user: %w", err)
	}

	return permissions, nil
}

func scanPermissionRow(scan func(dest ...any) error) (*domain.Permission, error) {
	var (
		permission  domain.Permission
		description sql.NullString
	)

	if err := scan(
		&permission.ID,
		&permission.Name,
		&permission.ServiceNamespace,
		&permission.Action,
		&description,
	); err != nil {
		return nil, err
	}

	if description.Valid {
		desc := description.String
		permission.Description = &desc
	}

	return &permission, nil
}

var _ port.PermissionRepository = (*PermissionRepository)(nil)
