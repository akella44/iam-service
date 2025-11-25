package redis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	red "github.com/redis/go-redis/v9"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
)

const defaultJTIDenylistSnapshotKey = "iam:jti_denylist:snapshot"

// JTIDenylistSnapshotRepository persists denylist snapshots for warm starts.
type JTIDenylistSnapshotRepository struct {
	client *red.Client
	key    string
	ttl    time.Duration
}

// NewJTIDenylistSnapshotRepository wires Redis storage for denylist snapshots.
func NewJTIDenylistSnapshotRepository(client *red.Client, key string, ttl time.Duration) *JTIDenylistSnapshotRepository {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		trimmedKey = defaultJTIDenylistSnapshotKey
	}

	return &JTIDenylistSnapshotRepository{client: client, key: trimmedKey, ttl: ttl}
}

// SaveSnapshot stores the supplied snapshot payload with an optional TTL.
func (r *JTIDenylistSnapshotRepository) SaveSnapshot(ctx context.Context, snapshot domain.JTIDenylistSnapshot) error {
	if r == nil {
		return fmt.Errorf("snapshot repository not configured")
	}
	if r.client == nil {
		return fmt.Errorf("redis client not configured")
	}
	if len(snapshot.Payload) == 0 {
		return fmt.Errorf("snapshot payload required")
	}

	envelope := snapshotEnvelope{
		SnapshotID:  snapshot.SnapshotID,
		GeneratedAt: snapshot.GeneratedAt.UTC(),
		Checksum:    snapshot.Checksum,
		Payload:     base64.StdEncoding.EncodeToString(snapshot.Payload),
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode snapshot envelope: %w", err)
	}

	expiration := r.ttl
	if expiration < 0 {
		expiration = 0
	}

	if err := r.client.Set(ctx, r.key, data, expiration).Err(); err != nil {
		return fmt.Errorf("redis set denylist snapshot: %w", err)
	}

	return nil
}

// LoadLatestSnapshot retrieves the most recent snapshot when present.
func (r *JTIDenylistSnapshotRepository) LoadLatestSnapshot(ctx context.Context) (*domain.JTIDenylistSnapshot, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("snapshot repository not configured")
	}

	data, err := r.client.Get(ctx, r.key).Bytes()
	if err != nil {
		if errors.Is(err, red.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis get denylist snapshot: %w", err)
	}

	var envelope snapshotEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode snapshot envelope: %w", err)
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode snapshot payload: %w", err)
	}

	snapshot := &domain.JTIDenylistSnapshot{
		SnapshotID:  envelope.SnapshotID,
		GeneratedAt: envelope.GeneratedAt,
		Payload:     payload,
		Checksum:    envelope.Checksum,
	}
	return snapshot, nil
}

type snapshotEnvelope struct {
	SnapshotID  string    `json:"snapshot_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Checksum    string    `json:"checksum"`
	Payload     string    `json:"payload"`
}

var _ port.JTIDenylistSnapshotStore = (*JTIDenylistSnapshotRepository)(nil)
