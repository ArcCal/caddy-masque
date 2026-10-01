package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Printed by masque-vpn's masque-passwd (the Rust argon2 crate).
const (
	rustHash     = "$argon2id$v=19$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8"
	rustPassword = "Lz4Iwq-Zj-Nypqg4TUubfWV_"
)

func TestHashesFromMasquePasswdVerify(t *testing.T) {
	if err := ValidateHash(rustHash); err != nil {
		t.Fatal(err)
	}
	if !verifyHash(rustPassword, rustHash) || verifyHash(rustPassword+"x", rustHash) {
		t.Fatal("cross-implementation verification")
	}
}

func TestOwnHashesVerify(t *testing.T) {
	h := HashPassword("correct horse battery")
	if err := ValidateHash(h); err != nil || !verifyHash("correct horse battery", h) || verifyHash("wrong", h) {
		t.Fatal(h, err)
	}
	if h[:30] != "$argon2id$v=19$m=19456,t=2,p=1" {
		t.Fatal(h)
	}
}

func TestBadHashes(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2i$v=19$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=16$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=19$m=99999999,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=19$m=19456,t=2$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8"} {
		if ValidateHash(h) == nil {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestBasic(t *testing.T) {
	h := BasicAuthorization("laptop", "p:a ss")
	if u, p, ok := ParseBasic(h); !ok || u != "laptop" || p != "p:a ss" {
		t.Fatal(u, p)
	}
	// RFC 7617 example.
	if u, p, ok := ParseBasic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="); !ok || u != "Aladdin" || p != "open sesame" {
		t.Fatal(u, p)
	}
	if u, _, _ := ParseBasic("basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="); u != "Aladdin" {
		t.Fatal("scheme is case-insensitive")
	}
	for _, bad := range []string{"Bearer abc", "Basic", "Basic !!!", "Basic bm9jb2xvbg==", "\xff\xfe"} {
		if _, _, ok := ParseBasic(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUserNames(t *testing.T) {
	for _, ok := range []string{"alice", "a.b-c_d", "x"} {
		if ValidateUserName(ok) != nil {
			t.Error(ok)
		}
	}
	for _, bad := range []string{"", ".hidden", "a:b", "a b", "é", string(make([]byte, 65))} {
		if ValidateUserName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestVerify(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	ctx := context.Background()
	u, ok, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword))
	if !ok || err != nil || u.Name != "alice" {
		t.Fatal(u, ok, err)
	}
	for _, h := range []string{BasicAuthorization("alice", "nope"), BasicAuthorization("mallory", rustPassword), ""} {
		if _, ok, _ := a.Verify(ctx, h); ok {
			t.Errorf("%q accepted", h)
		}
	}
	// Removed, or password changed: no longer current.
	a.Replace(map[string]string{"alice": HashPassword("new")})
	if a.IsCurrent(u) {
		t.Fatal("stale user")
	}
	if _, ok, _ := a.Verify(ctx, BasicAuthorization("alice", rustPassword)); ok {
		t.Fatal("old password")
	}
}

func TestFullQueueIsAnsweredAtOnce(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	busy := 0
	a.OnBusy = func() { busy++ }
	// Take every slot.
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, a.maxWaiting)
	for range a.maxWaiting {
		go func() {
			_, _, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword))
			done <- err
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for a.waiting.Load() != a.maxWaiting {
		if time.Now().After(deadline) {
			t.Fatal("not all waiting", a.waiting.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if _, _, err := a.Verify(context.Background(), BasicAuthorization("alice", rustPassword)); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, _, err := a.Verify(context.Background(), BasicAuthorization("alice", rustPassword)); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if busy != 1 {
		t.Fatal("warned", busy)
	}
	if _, ok, err := a.Verify(context.Background(), ""); ok || err != nil {
		t.Fatal("no credentials: answered as before")
	}
	// Cancelled requests leave the queue.
	cancel()
	for range a.maxWaiting {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if a.waiting.Load() != 0 {
		t.Fatal(a.waiting.Load())
	}
	for range cap(a.slots) {
		<-a.slots
	}
	if _, ok, err := a.Verify(context.Background(), BasicAuthorization("alice", rustPassword)); !ok || err != nil {
		t.Fatal(ok, err)
	}
}
