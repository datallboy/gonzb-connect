package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"sync"
	"testing"

	"github.com/datallboy/gonzb-connect/protocol"
)

func TestStoreConcurrentEnrollmentBinding(t *testing.T) {
	databaseURL := os.Getenv("GONZB_CONNECT_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("GONZB_CONNECT_TEST_DATABASE_URL is not configured")
	}
	ctx := context.Background()
	store, err := OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	token, err := store.CreateEnrollment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tokenID, _, err := parseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM node_enrollments WHERE token_id = $1`, tokenID)
	})

	type identity struct {
		nodeID    string
		publicKey string
	}
	identities := make([]identity, 2)
	for i := range identities {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identities[i] = identity{
			nodeID:    protocol.NodeIDFromPublicKey(publicKey),
			publicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		}
	}

	start := make(chan struct{})
	results := make(chan error, len(identities))
	var ready sync.WaitGroup
	ready.Add(len(identities))
	for _, candidate := range identities {
		go func(candidate identity) {
			ready.Done()
			<-start
			results <- store.BindEnrollment(ctx, token, candidate.nodeID, candidate.publicKey)
		}(candidate)
	}
	ready.Wait()
	close(start)

	succeeded := 0
	for range identities {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent enrollment binding successes = %d, want 1", succeeded)
	}

	var boundNodeID, boundPublicKey string
	if err := store.pool.QueryRow(ctx, `
		SELECT bound_node_id, bound_public_key FROM node_enrollments WHERE token_id = $1`, tokenID).
		Scan(&boundNodeID, &boundPublicKey); err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, candidate := range identities {
		if boundNodeID == candidate.nodeID && boundPublicKey == candidate.publicKey {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatal("enrollment was not atomically bound to either contender")
	}
}
