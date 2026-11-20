package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type moderationCase struct {
	ID             uint64    `json:"id"`
	Action         string    `json:"action"`
	TargetID       string    `json:"target_id"`
	TargetName     string    `json:"target_name"`
	ModeratorID    string    `json:"moderator_id"`
	ModeratorName  string    `json:"moderator_name"`
	Reason         string    `json:"reason"`
	Duration       string    `json:"duration,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	Active         bool      `json:"active"`
	ResolvedAt     time.Time `json:"resolved_at,omitempty"`
	Resolution     string    `json:"resolution,omitempty"`
	ResolvedByID   string    `json:"resolved_by_id,omitempty"`
	ResolvedByName string    `json:"resolved_by_name,omitempty"`
}

type caseFile struct {
	NextID uint64           `json:"next_id"`
	Cases  []moderationCase `json:"cases"`
}

// caseRetention is the moderation-record period stated in the privacy policy:
// one year, so moderators can see repeat behaviour and why someone was
// banned. Everything else the bots keep is deleted after 20 days. Case
// numbers keep counting regardless.
const caseRetention = 365 * 24 * time.Hour

type caseStore struct {
	mu   sync.Mutex
	path string
	data caseFile
	now  func() time.Time
}

func openCaseStore(dir string) (*caseStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create moderation state directory: %w", err)
	}
	store := &caseStore{path: filepath.Join(dir, "cases.json"), data: caseFile{NextID: 1}, now: time.Now}
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read moderation cases: %w", err)
	}
	if err := json.Unmarshal(raw, &store.data); err != nil {
		return nil, fmt.Errorf("decode moderation cases: %w", err)
	}
	if store.data.NextID == 0 {
		store.data.NextID = 1
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.pruneLocked() {
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// pruneLocked drops cases older than caseRetention and reports whether any
// were removed.
func (s *caseStore) pruneLocked() bool {
	cutoff := s.now().UTC().Add(-caseRetention)
	kept := s.data.Cases[:0]
	for _, entry := range s.data.Cases {
		if entry.CreatedAt.After(cutoff) {
			kept = append(kept, entry)
		}
	}
	removed := len(kept) != len(s.data.Cases)
	s.data.Cases = kept
	return removed
}

// prune deletes expired cases now; run it periodically so old cases go away
// even when nobody uses the moderation commands.
func (s *caseStore) prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pruneLocked() {
		return nil
	}
	return s.saveLocked()
}

func (s *caseStore) pruneEvery(interval time.Duration) {
	for range time.Tick(interval) {
		_ = s.prune()
	}
}

func (s *caseStore) add(entry moderationCase) (moderationCase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	entry.ID = s.data.NextID
	s.data.NextID++
	entry.CreatedAt = s.now().UTC()
	entry.Active = entry.Action == "warn" || entry.Action == "timeout" || entry.Action == "ban"
	s.data.Cases = append(s.data.Cases, entry)
	return entry, s.saveLocked()
}

func (s *caseStore) get(id uint64) (moderationCase, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruneLocked() {
		_ = s.saveLocked()
	}
	for _, entry := range s.data.Cases {
		if entry.ID == id {
			return entry, true
		}
	}
	return moderationCase{}, false
}

func (s *caseStore) activeWarnings(targetID string) []moderationCase {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruneLocked() {
		_ = s.saveLocked()
	}
	var out []moderationCase
	for _, entry := range s.data.Cases {
		if entry.Action == "warn" && entry.Active && entry.TargetID == targetID {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (s *caseStore) resolveWarning(id uint64, moderatorID, moderatorName, reason string) (moderationCase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.data.Cases {
		entry := &s.data.Cases[index]
		if entry.ID != id {
			continue
		}
		if entry.Action != "warn" {
			return moderationCase{}, fmt.Errorf("case #%d is not a warning", id)
		}
		if !entry.Active {
			return moderationCase{}, fmt.Errorf("warning #%d is already resolved", id)
		}
		entry.Active = false
		entry.ResolvedAt = s.now().UTC()
		entry.Resolution = reason
		entry.ResolvedByID = moderatorID
		entry.ResolvedByName = moderatorName
		return *entry, s.saveLocked()
	}
	return moderationCase{}, fmt.Errorf("warning #%d does not exist", id)
}

func (s *caseStore) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode moderation cases: %w", err)
	}
	temporary := s.path + ".tmp"
	if err := os.WriteFile(temporary, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write moderation cases: %w", err)
	}
	if err := os.Rename(temporary, s.path); err != nil {
		// Windows does not replace an existing destination atomically.
		if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replace moderation cases: %w", err)
		}
		if retryErr := os.Rename(temporary, s.path); retryErr != nil {
			return fmt.Errorf("replace moderation cases: %w", retryErr)
		}
	}
	return nil
}

func moderationDataDir() string {
	if state := os.Getenv("STATE_DIRECTORY"); state != "" {
		return state
	}
	if configured := os.Getenv("WINDISSECT_DATA_DIR"); configured != "" {
		return configured
	}
	return "data"
}
