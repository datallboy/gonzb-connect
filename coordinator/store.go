package coordinator

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

type Store struct{ pool *pgxpool.Pool }

func OpenStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, strings.TrimSpace(databaseURL))
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	store := &Store{pool: pool}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS node_enrollments (
		  token_id TEXT PRIMARY KEY,
		  token_hash TEXT NOT NULL,
		  bound_node_id TEXT,
		  bound_public_key TEXT,
		  revoked_at TIMESTAMPTZ,
		  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		  last_used_at TIMESTAMPTZ
		);
		CREATE INDEX IF NOT EXISTS idx_node_enrollments_bound_node
		  ON node_enrollments(bound_node_id) WHERE revoked_at IS NULL;`)
	return err
}

func (s *Store) CreateEnrollment(ctx context.Context) (string, error) {
	tokenID, err := randomTokenPart(12)
	if err != nil {
		return "", err
	}
	secret, err := randomTokenPart(32)
	if err != nil {
		return "", err
	}
	hash, err := hashToken(secret)
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO node_enrollments (token_id, token_hash) VALUES ($1, $2)`, tokenID, hash); err != nil {
		return "", err
	}
	return "gzc_" + tokenID + "." + secret, nil
}

func (s *Store) BindEnrollment(ctx context.Context, token, nodeID, publicKey string) error {
	tokenID, secret, err := parseToken(token)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var encodedHash string
	var boundNodeID, boundPublicKey *string
	var revokedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT token_hash, bound_node_id, bound_public_key, revoked_at
		FROM node_enrollments WHERE token_id = $1 FOR UPDATE`, tokenID).Scan(&encodedHash, &boundNodeID, &boundPublicKey, &revokedAt); err != nil {
		return fmt.Errorf("invalid enrollment token")
	}
	if revokedAt != nil || !verifyToken(secret, encodedHash) {
		return fmt.Errorf("invalid or revoked enrollment token")
	}
	if boundNodeID != nil && (*boundNodeID != nodeID || boundPublicKey == nil || *boundPublicKey != publicKey) {
		return fmt.Errorf("enrollment token is bound to another node")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_enrollments
		SET bound_node_id = COALESCE(bound_node_id, $2),
		    bound_public_key = COALESCE(bound_public_key, $3), last_used_at = NOW()
		WHERE token_id = $1`, tokenID, nodeID, publicKey); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeEnrollment(ctx context.Context, tokenID string) (bool, error) {
	result, err := s.pool.Exec(ctx, `UPDATE node_enrollments SET revoked_at = NOW() WHERE token_id = $1 AND revoked_at IS NULL`, strings.TrimSpace(tokenID))
	return result.RowsAffected() > 0, err
}

func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func hashToken(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(secret), salt, 3, 64*1024, 2, 32)
	return base64.RawURLEncoding.EncodeToString(salt) + "." + base64.RawURLEncoding.EncodeToString(hash), nil
}

func verifyToken(secret, encoded string) bool {
	saltRaw, hashRaw, ok := strings.Cut(encoded, ".")
	if !ok {
		return false
	}
	salt, err1 := base64.RawURLEncoding.DecodeString(saltRaw)
	expected, err2 := base64.RawURLEncoding.DecodeString(hashRaw)
	if err1 != nil || err2 != nil || len(salt) != 16 || len(expected) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(secret), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func parseToken(token string) (string, string, error) {
	if token != strings.TrimSpace(token) || !strings.HasPrefix(token, "gzc_") {
		return "", "", fmt.Errorf("invalid enrollment token")
	}
	raw := strings.TrimPrefix(token, "gzc_")
	tokenID, secret, ok := strings.Cut(raw, ".")
	if !ok || strings.Contains(secret, ".") || len(tokenID) != 16 || len(secret) != 43 || !validTokenPart(tokenID) || !validTokenPart(secret) {
		return "", "", fmt.Errorf("invalid enrollment token")
	}
	return tokenID, secret, nil
}

func validTokenPart(value string) bool {
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func randomTokenPart(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
