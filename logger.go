package main

import (
	"encoding/json"
	"os"
	"sync"
)

// LogEntry records one incoming DNS request
// rate limiter fires for the first time on an IP
type LogEntry struct {
	EventType     string `json:"event_type"`
	Timestamp     string `json:"timestamp"`
	SourceIP      string `json:"source_ip"`
	SourcePort    int    `json:"source_port"`
	QueriedDomain string `json:"queried_domain"`
	QueryType     string `json:"query_type"`
	EDNSPayload   uint16 `json:"edns_payload"`
	RequestSize   int    `json:"request_size"`
	ResponseSize  int    `json:"response_size"`
}

// EventEntry records classifier events
// Kept separate from LogEntry so the analysis pipeline can filter by event_type
type EventEntry struct {
	EventType   string `json:"event_type"`
	Timestamp   string `json:"timestamp"`
	SourceIP    string `json:"source_ip"`
	AttackCount int    `json:"attack_count"`
	Domain      string `json:"domain,omitempty"`
	QueryType   string `json:"query_type,omitempty"`
	AttackStart string `json:"attack_start,omitempty"`
	AttackEnd   string `json:"attack_end,omitempty"`
}

var (
	logFile *os.File
	logMu   sync.Mutex
)

func initLogger(path string) error {
	var err error
	logFile, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	return err
}

func closeLogger() {
	if logFile != nil {
		logFile.Close()
	}
}

func writeLog(entry LogEntry) {
	writeLine(entry)
}

func writeEvent(entry EventEntry) {
	writeLine(entry)
}

func writeLine(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	logFile.Write(data)
	logFile.Write([]byte{'\n'})
}
