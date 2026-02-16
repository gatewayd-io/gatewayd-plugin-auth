package plugin

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionManager_GetOrCreate(t *testing.T) {
	sm := NewSessionManager(time.Hour)

	sess1 := sm.GetOrCreate("client1")
	require.NotNil(t, sess1)
	assert.Equal(t, StateInit, sess1.State)

	// Same key returns same session.
	sess2 := sm.GetOrCreate("client1")
	assert.Equal(t, sess1, sess2)

	// Different key returns different session.
	sess3 := sm.GetOrCreate("client2")
	assert.NotEqual(t, sess1, sess3)
}

func TestSessionManager_Get(t *testing.T) {
	sm := NewSessionManager(time.Hour)

	assert.Nil(t, sm.Get("nonexistent"))

	sm.GetOrCreate("client1")
	sess := sm.Get("client1")
	assert.NotNil(t, sess)
}

func TestSessionManager_Remove(t *testing.T) {
	sm := NewSessionManager(time.Hour)

	sm.GetOrCreate("client1")
	assert.Equal(t, 1, sm.Count())

	sm.Remove("client1")
	assert.Equal(t, 0, sm.Count())
	assert.Nil(t, sm.Get("client1"))
}

func TestSessionManager_IsAuthenticated(t *testing.T) {
	sm := NewSessionManager(time.Hour)

	assert.False(t, sm.IsAuthenticated("client1"))

	sess := sm.GetOrCreate("client1")
	assert.False(t, sm.IsAuthenticated("client1"))

	sess.State = StateAuthenticated
	assert.True(t, sm.IsAuthenticated("client1"))
}

func TestSessionManager_Cleanup(t *testing.T) {
	sm := NewSessionManager(100 * time.Millisecond)

	sm.GetOrCreate("client1")
	sm.GetOrCreate("client2")
	assert.Equal(t, 2, sm.Count())

	time.Sleep(200 * time.Millisecond)
	sm.Cleanup()
	assert.Equal(t, 0, sm.Count())
}

func TestSessionManager_ConcurrentAccess(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	const goroutines = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			key := "client" + string(rune('A'+n%26))
			sess := sm.GetOrCreate(key)
			sess.State = StateAuthenticated
			sm.IsAuthenticated(key)
			if n%3 == 0 {
				sm.Remove(key)
			}
		}(i)
	}

	wg.Wait()
	// No panics = success.
}

func TestSessionManager_CleanupLoop(t *testing.T) {
	sm := NewSessionManager(50 * time.Millisecond)
	done := make(chan struct{})

	sm.GetOrCreate("client1")
	assert.Equal(t, 1, sm.Count())

	sm.StartCleanupLoop(30*time.Millisecond, done)

	// Wait for cleanup to run.
	time.Sleep(200 * time.Millisecond)
	close(done)

	assert.Equal(t, 0, sm.Count())
}
