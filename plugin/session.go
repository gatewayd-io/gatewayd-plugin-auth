package plugin

import (
	"sync"
	"time"
)

// Session holds the authentication state for a single client connection.
type Session struct {
	State           AuthState
	Username        string
	Database        string
	AuthMethod      AuthType
	Salt            [SaltSize]byte     // per-connection salt for MD5
	ScramState      *ScramServerState  // multi-round SCRAM state
	Roles           []string           // populated after auth for authorization
	CreatedAt       time.Time
	AuthenticatedAt time.Time
}

// ScramServerState holds the server-side state for a SCRAM-SHA-256 handshake.
type ScramServerState struct {
	ServerFirstMsg []byte
	AuthID         string
	Conversation   interface{} // *scram.ServerConversation from xdg-go/scram
}

// SessionManager provides thread-safe session tracking for client connections.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session // key = client remote address
	ttl      time.Duration
}

// NewSessionManager creates a new SessionManager with the given session TTL.
func NewSessionManager(ttl time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
	return sm
}

// GetOrCreate returns the session for the given key, creating a new one if it doesn't exist.
func (sm *SessionManager) GetOrCreate(key string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sess, ok := sm.sessions[key]; ok {
		return sess
	}

	sess := &Session{
		State:     StateInit,
		CreatedAt: time.Now(),
	}
	sm.sessions[key] = sess
	return sess
}

// Get returns the session for the given key, or nil if not found.
func (sm *SessionManager) Get(key string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[key]
}

// Remove deletes the session for the given key.
func (sm *SessionManager) Remove(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, key)
}

// IsAuthenticated returns true if the session exists and is in the Authenticated state.
func (sm *SessionManager) IsAuthenticated(key string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessions[key]
	return ok && sess.State == StateAuthenticated
}

// Cleanup removes all sessions older than the TTL.
func (sm *SessionManager) Cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for key, sess := range sm.sessions {
		if now.Sub(sess.CreatedAt) > sm.ttl {
			delete(sm.sessions, key)
		}
	}
}

// StartCleanupLoop starts a background goroutine that periodically cleans up expired sessions.
func (sm *SessionManager) StartCleanupLoop(interval time.Duration, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sm.Cleanup()
			case <-done:
				return
			}
		}
	}()
}

// Count returns the number of active sessions.
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}
