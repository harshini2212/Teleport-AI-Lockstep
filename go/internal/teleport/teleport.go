// Package teleport is a thin, in-memory mock of the Teleport auth-service API
// client. The Client interface mirrors the real methods on
// *github.com/gravitational/teleport/api/client.Client so the engine code is
// written exactly as it would be against a live cluster; only the constructor
// differs. Swapping NewMock() for client.New(ctx, client.Config{...}) makes this
// run against a real Teleport Auth Server.
//
// Real-client correspondence:
//
//	UpsertUser   -> client.UpsertUser / CreateUser
//	DeleteUser   -> client.DeleteUser
//	GetUser      -> client.GetUser
//	CreateLock   -> client.UpsertLock (types.Lock)
//	ListSessions -> client.GetActiveSessionTrackers
package teleport

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// User is the subset of types.User the lifecycle engine touches.
type User struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
	// Traits feed Teleport role templates (logins, kube_groups, etc).
	Traits map[string][]string `json:"traits,omitempty"`
}

// Lock mirrors types.Lock — a lock immediately severs a target's active access
// cluster-wide, which is how we contain a compromised or offboarded identity.
type Lock struct {
	Target  string    `json:"target"`
	Reason  string    `json:"reason"`
	Expires time.Time `json:"expires,omitempty"` // zero = permanent until cleared
}

// Session mirrors a session tracker — an in-progress SSH/kube/db session.
type Session struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Kind     string    `json:"kind"` // "ssh" | "k8s" | "db"
	Login    string    `json:"login"`
	SourceIP string    `json:"source_ip"`
	Started  time.Time `json:"started"`
}

// Client is the access-plane surface the engine depends on.
type Client interface {
	UpsertUser(ctx context.Context, u User) error
	GetUser(ctx context.Context, name string) (User, bool, error)
	DeleteUser(ctx context.Context, name string) error
	CreateLock(ctx context.Context, l Lock) error
	ListLocks(ctx context.Context) ([]Lock, error)
	ListSessions(ctx context.Context) ([]Session, error)
}

// Mock is an in-memory Client (and WorkloadClient — see workload.go) for tests
// and the offline demo.
type Mock struct {
	mu       sync.Mutex
	users    map[string]User
	locks    map[string]Lock
	sessions map[string]Session
	// Workload/agent identity state (see workload.go).
	wis  map[string]WorkloadIdentity
	bots map[string]Bot
}

// NewMock returns an empty in-memory cluster.
func NewMock() *Mock {
	return &Mock{
		users:    map[string]User{},
		locks:    map[string]Lock{},
		sessions: map[string]Session{},
		wis:      map[string]WorkloadIdentity{},
		bots:     map[string]Bot{},
	}
}

// SeedSession injects an active session — used by the demo to model an
// already-running session at the moment an identity is offboarded.
func (m *Mock) SeedSession(s Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
}

// RemoveSession ends (deletes) an active session — models terminating a live
// Teleport session (`tsh sessions kill` / `tctl sessions`).
func (m *Mock) RemoveSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *Mock) UpsertUser(_ context.Context, u User) error {
	if u.Name == "" {
		return fmt.Errorf("user name required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	roles := append([]string(nil), u.Roles...)
	sort.Strings(roles)
	u.Roles = roles
	m.users[u.Name] = u
	return nil
}

func (m *Mock) GetUser(_ context.Context, name string) (User, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[name]
	return u, ok, nil
}

func (m *Mock) DeleteUser(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, name)
	return nil
}

func (m *Mock) CreateLock(_ context.Context, l Lock) error {
	if l.Target == "" {
		return fmt.Errorf("lock target required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locks[l.Target] = l
	return nil
}

func (m *Mock) ListLocks(_ context.Context) ([]Lock, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Lock, 0, len(m.locks))
	for _, l := range m.locks {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, nil
}

// AllUsers returns every provisioned user. The real client exposes this via
// GetUsers(ctx, false); the audit package consumes it through a narrow
// interface assertion so it stays decoupled from *Mock.
func (m *Mock) AllUsers(_ context.Context) []User {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Mock) ListSessions(_ context.Context) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
