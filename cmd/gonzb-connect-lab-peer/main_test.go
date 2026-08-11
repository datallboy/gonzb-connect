package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityPersistsAndDerivesStableNodeID(t *testing.T) {
	fileName := filepath.Join(t.TempDir(), "identity")
	first, created, err := loadOrCreateIdentity(fileName)
	if err != nil || !created {
		t.Fatalf("create identity: created=%v err=%v", created, err)
	}
	second, created, err := loadOrCreateIdentity(fileName)
	if err != nil || created {
		t.Fatalf("reload identity: created=%v err=%v", created, err)
	}
	firstID, _ := first.NodeID(context.Background())
	secondID, _ := second.NodeID(context.Background())
	if firstID != secondID {
		t.Fatalf("node ID changed: %q != %q", firstID, secondID)
	}
	info, err := os.Stat(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %o", info.Mode().Perm())
	}
}

func TestDeterministicBodyIncludesCanaryAndVariesByRequest(t *testing.T) {
	canary := []byte("unique-canary")
	first := deterministicBody(1, 1024, canary)
	second := deterministicBody(2, 1024, canary)
	if !bytes.HasPrefix(first, canary) || bytes.Equal(first, second) {
		t.Fatal("deterministic workload body is invalid")
	}
	if got := deterministicBody(1, 4, canary); !bytes.Equal(got, canary[:4]) {
		t.Fatalf("truncated canary = %q", got)
	}
}

func TestRequiredSecretRejectsWhitespaceAndBounds(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid")
	if err := os.WriteFile(valid, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readRequiredFile(valid, 16); err != nil || string(got) != "secret" {
		t.Fatalf("valid secret = %q, %v", got, err)
	}
	bad := filepath.Join(directory, "bad")
	if err := os.WriteFile(bad, []byte("two words"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRequiredFile(bad, 16); err == nil {
		t.Fatal("secret containing whitespace was accepted")
	}
}
