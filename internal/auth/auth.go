// Package auth checks user names and passwords. RFC 9484 §11 names HTTP
// authentication with the Authorization header as one way to restrict IP
// proxying to authorized users. Clients send HTTP Basic credentials (RFC
// 7617) with every CONNECT-IP request, unprompted, as RFC 9110 §11.6.2
// allows; TLS protects the password. The server keeps only Argon2id hashes
// (RFC 9106) in PHC string format, the same as masque-vpn's masque-passwd
// prints, so its user lists work unchanged.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// MinPasswordLen is the shortest password the passwd command accepts.
const MinPasswordLen = 12

// ValidateUserName checks a name: it appears in logs and must not contain
// ':', which separates name and password in Basic credentials.
func ValidateUserName(name string) error {
	ok := name != "" && len(name) <= 64 && name[0] != '.'
	for i := 0; ok && i < len(name); i++ {
		c := name[i]
		ok = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
	}
	if !ok {
		return errors.New("user name must be 1-64 characters of letters, digits, '-', '_' or '.', and not start with '.'")
	}
	return nil
}

// BasicAuthorization is the Authorization value for Basic credentials.
func BasicAuthorization(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// ParseBasic parses a Basic Authorization value into name and password.
func ParseBasic(value string) (string, string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(value), " ")
	if !ok || !strings.EqualFold(scheme, "basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", "", false
	}
	user, password, ok := strings.Cut(string(decoded), ":")
	return user, password, ok
}

// GeneratePassword is a random password with 144 bits of entropy: out of
// reach of online guessing, so the server needs no lockout.
func GeneratePassword() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Argon2id parameters of the argon2 crate's defaults that masque-passwd
// uses: 19 MiB, 2 passes, 1 lane (the OWASP recommendation).
const (
	defaultMemory  = 19456
	defaultTime    = 2
	defaultThreads = 1
	defaultKeyLen  = 32
)

// HashPassword is the Argon2id PHC string of a password.
func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte(password), salt, defaultTime, defaultMemory, defaultThreads, defaultKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", defaultMemory, defaultTime, defaultThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

type phc struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

// Limits on accepted parameters, so a configured hash cannot make the
// server allocate gigabytes or spin for minutes per login.
const (
	maxMemory = 1 << 20 // 1 GiB in KiB
	maxTime   = 64
)

func parsePHC(s string) (phc, error) {
	parts := strings.Split(s, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return phc{}, errors.New("password hash must be an argon2id PHC string")
	}
	if parts[2] != "v=19" {
		return phc{}, errors.New("password hash must use Argon2 version 19")
	}
	var h phc
	seen := map[string]bool{}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil || seen[k] {
			return phc{}, errors.New("invalid argon2 parameters")
		}
		seen[k] = true
		switch k {
		case "m":
			h.memory = uint32(n)
		case "t":
			h.time = uint32(n)
		case "p":
			if n > 255 {
				return phc{}, errors.New("invalid argon2 parameters")
			}
			h.threads = uint8(n)
		default:
			return phc{}, errors.New("invalid argon2 parameters")
		}
	}
	if !seen["m"] || !seen["t"] || !seen["p"] || h.time == 0 || h.threads == 0 ||
		h.memory < 8*uint32(h.threads) || h.memory > maxMemory || h.time > maxTime {
		return phc{}, errors.New("invalid argon2 parameters")
	}
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.salt) < 8 {
		return phc{}, errors.New("invalid salt in password hash")
	}
	if h.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.key) < 16 {
		return phc{}, errors.New("invalid hash in password hash")
	}
	return h, nil
}

// ValidateHash checks a configured hash.
func ValidateHash(s string) error {
	_, err := parsePHC(s)
	return err
}

func verifyHash(password, hash string) bool {
	h, err := parsePHC(hash)
	if err != nil {
		return false
	}
	key := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(key, h.key) == 1
}

// User is an authenticated user as a session records it.
type User struct {
	Name string
	// The hash the user authenticated against; a reload that changes it
	// ends the user's sessions.
	Hash string
}

// ErrBusy means too many requests, in all or from one source, wait for a
// password verification.
var ErrBusy = errors.New("too many requests waiting for password verification")

// waitingPerSlot bounds the queue: a full queue is worked through in a
// second or two.
const waitingPerSlot = 32

// perSource is how many verifications one source (see sourceKey) may have
// waiting or running at once. Users behind one address (a shared NAT) who
// are past this get 503 and retry; with their credentials remembered they
// skip the queue anyway.
const perSource = 4

// rememberFor is how long verified credentials are remembered after their
// last use.
const rememberFor = 12 * time.Hour

// Authenticator verifies credentials against the configured users.
type Authenticator struct {
	mu    sync.RWMutex
	users map[string]string // name -> hash
	// Hashing takes tens of milliseconds and megabytes, so verifications
	// run at most len(slots) at a time.
	slots chan struct{}
	// Requests waiting for a slot, bounded so a flood of made-up
	// credentials cannot queue without end ahead of real users.
	waiting    atomic.Int64
	maxWaiting int64
	// Unknown names also incur a password verification. Its cost matches
	// generated hashes; custom PHC parameters can have different costs.
	dummyHash string
	// Called (at most once a minute) when the queue is full.
	OnBusy   func()
	lastBusy atomic.Int64

	// Credentials verified recently, so a returning user needs no Argon2
	// verification and is never turned away while a flood of made-up
	// credentials fills the queue. Keyed by an HMAC of name and password
	// under cacheKey, which exists only in memory; the value is the hash
	// the password matched and when it last did. Only correct passwords
	// get in, so there is at most one entry per user and hash.
	verifiedMu sync.Mutex
	verified   map[[sha256.Size]byte]remembered
	cacheKey   []byte

	// Verifications waiting or running per source, so that one source
	// cannot fill the queue.
	sourcesMu sync.Mutex
	sources   map[netip.Addr]int
}

type remembered struct {
	hash string
	at   time.Time
}

// New makes an authenticator with no users.
func New() *Authenticator {
	slots := runtime.NumCPU() * 2
	cacheKey := make([]byte, 32)
	if _, err := rand.Read(cacheKey); err != nil {
		panic(err)
	}
	return &Authenticator{users: map[string]string{}, slots: make(chan struct{}, slots),
		maxWaiting: int64(slots * waitingPerSlot), dummyHash: HashPassword(GeneratePassword()),
		verified: map[[sha256.Size]byte]remembered{}, cacheKey: cacheKey, sources: map[netip.Addr]int{}}
}

// Replace installs a new user list (name -> hash).
func (a *Authenticator) Replace(users map[string]string) {
	m := make(map[string]string, len(users))
	for k, v := range users {
		m[k] = v
	}
	a.mu.Lock()
	a.users = m
	a.mu.Unlock()
}

// IsCurrent reports whether a user is still configured with the same hash.
func (a *Authenticator) IsCurrent(u User) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	h, ok := a.users[u.Name]
	return ok && h == u.Hash
}

// Remembered checks an Authorization header value against the credentials
// verified within rememberFor, without a hash verification; a hit counts as
// a new use. Credentials whose user has a different hash now never match.
func (a *Authenticator) Remembered(authorization string) (User, bool) {
	name, password, ok := ParseBasic(authorization)
	if !ok {
		return User{}, false
	}
	a.mu.RLock()
	hash, known := a.users[name]
	a.mu.RUnlock()
	if !known || !a.recall(a.tag(name, password), hash) {
		return User{}, false
	}
	return User{Name: name, Hash: hash}, true
}

// Verify checks an Authorization header value sent from source. Requests
// without credentials are answered at once; only those that carry them pay
// for a hash verification, unless the same credentials were verified
// recently (see Remembered). It returns ok false for wrong or missing
// credentials, and ErrBusy when too many requests, in all or from this
// source, already wait for a verification. Requests whose source is not
// known (an invalid address) count as one source.
// A cancelled context returns at once, but the verification keeps its slot,
// and its source's place, until the hashing it started has finished.
func (a *Authenticator) Verify(ctx context.Context, authorization string, source netip.Addr) (User, bool, error) {
	name, password, ok := ParseBasic(authorization)
	if !ok {
		return User{}, false, nil
	}
	a.mu.RLock()
	hash, known := a.users[name]
	a.mu.RUnlock()
	tag := a.tag(name, password)
	if known && a.recall(tag, hash) {
		return User{Name: name, Hash: hash}, true, nil
	}
	if !known {
		hash = a.dummyHash
	}
	src := sourceKey(source)
	if !a.enterSource(src) {
		return User{}, false, ErrBusy
	}
	// Given back here unless the hashing goroutine has taken it over.
	leave := true
	defer func() {
		if leave {
			a.leaveSource(src)
		}
	}()
	select {
	case a.slots <- struct{}{}:
	default:
		if a.waiting.Add(1) > a.maxWaiting {
			a.waiting.Add(-1)
			a.warnBusy()
			return User{}, false, ErrBusy
		}
		select {
		case a.slots <- struct{}{}:
			a.waiting.Add(-1)
		case <-ctx.Done():
			a.waiting.Add(-1)
			return User{}, false, ctx.Err()
		}
	}
	result := make(chan bool, 1)
	leave = false
	go func() {
		defer func() {
			<-a.slots
			a.leaveSource(src)
		}()
		result <- verifyHash(password, hash)
	}()
	select {
	case ok = <-result:
	case <-ctx.Done():
		return User{}, false, ctx.Err()
	}
	u := User{Name: name, Hash: hash}
	ok = ok && known && a.IsCurrent(u)
	if ok {
		a.remember(tag, hash)
	}
	return u, ok, nil
}

// tag is the cache key of a user name and password.
func (a *Authenticator) tag(name, password string) [sha256.Size]byte {
	m := hmac.New(sha256.New, a.cacheKey)
	m.Write([]byte(name))
	m.Write([]byte{0})
	m.Write([]byte(password))
	var t [sha256.Size]byte
	m.Sum(t[:0])
	return t
}

// recall reports whether the credentials of tag matched hash within
// rememberFor, and if so counts this as a new match.
func (a *Authenticator) recall(tag [sha256.Size]byte, hash string) bool {
	a.verifiedMu.Lock()
	defer a.verifiedMu.Unlock()
	r, ok := a.verified[tag]
	if !ok || r.hash != hash || time.Since(r.at) >= rememberFor {
		return false
	}
	a.verified[tag] = remembered{hash, time.Now()}
	return true
}

func (a *Authenticator) remember(tag [sha256.Size]byte, hash string) {
	a.verifiedMu.Lock()
	defer a.verifiedMu.Unlock()
	for k, r := range a.verified {
		if time.Since(r.at) >= rememberFor {
			delete(a.verified, k)
		}
	}
	a.verified[tag] = remembered{hash, time.Now()}
}

// enterSource takes one of a source's places among the verifications in
// progress, if it has one left.
func (a *Authenticator) enterSource(src netip.Addr) bool {
	a.sourcesMu.Lock()
	defer a.sourcesMu.Unlock()
	if a.sources[src] >= perSource {
		return false
	}
	a.sources[src]++
	return true
}

func (a *Authenticator) leaveSource(src netip.Addr) {
	a.sourcesMu.Lock()
	defer a.sourcesMu.Unlock()
	if a.sources[src]--; a.sources[src] <= 0 {
		delete(a.sources, src)
	}
}

func (a *Authenticator) warnBusy() {
	now := time.Now().Unix()
	last := a.lastBusy.Load()
	if now-last >= 60 && a.lastBusy.CompareAndSwap(last, now) && a.OnBusy != nil {
		a.OnBusy()
	}
}
