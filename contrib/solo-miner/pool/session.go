package pool

import "sync"

type sessionMap map[string]*stratumClient

var (
	sessions    sessionMap
	sessionsMux sync.RWMutex
)

func initiateSessions() {
	sessions = make(sessionMap)
}

func addSession(client *stratumClient) {
	sessionsMux.Lock()
	defer sessionsMux.Unlock()
	sessions[client.sessionID] = client
}

func removeSession(sessionID string) {
	sessionsMux.Lock()
	defer sessionsMux.Unlock()
	delete(sessions, sessionID)
}

func getSessionCount() int {
	sessionsMux.RLock()
	defer sessionsMux.RUnlock()
	return len(sessions)
}
