package main

import (
	"testing"
	"time"
)

func TestCaseStorePersistsAndResolvesWarnings(t *testing.T) {
	dir := t.TempDir()
	store, err := openCaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := store.add(moderationCase{
		Action: "warn", TargetID: "10", TargetName: "target",
		ModeratorID: "20", ModeratorName: "mod", Reason: "reason",
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID != 1 || len(store.activeWarnings("10")) != 1 {
		t.Fatalf("unexpected warning: %#v", entry)
	}
	if _, err := store.resolveWarning(entry.ID, "20", "mod", "appeal accepted"); err != nil {
		t.Fatal(err)
	}
	reopened, err := openCaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if warnings := reopened.activeWarnings("10"); len(warnings) != 0 {
		t.Fatalf("resolved warning remained active: %#v", warnings)
	}
	got, ok := reopened.get(entry.ID)
	if !ok || got.Active || got.Resolution != "appeal accepted" {
		t.Fatalf("resolution did not persist: %#v", got)
	}
}

func TestCaseStoreDeletesCasesAfterTwentyDays(t *testing.T) {
	dir := t.TempDir()
	store, err := openCaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	clock := start
	store.now = func() time.Time { return clock }
	old, err := store.add(moderationCase{Action: "warn", TargetID: "10", Reason: "old"})
	if err != nil {
		t.Fatal(err)
	}
	clock = start.Add(19 * 24 * time.Hour)
	if _, ok := store.get(old.ID); !ok {
		t.Fatal("a 19-day-old case was deleted early")
	}
	clock = start.Add(20*24*time.Hour + time.Minute)
	if _, ok := store.get(old.ID); ok {
		t.Fatal("a case older than 20 days was kept")
	}
	if got := store.activeWarnings("10"); len(got) != 0 {
		t.Fatalf("expired warning still active: %#v", got)
	}
	next, err := store.add(moderationCase{Action: "warn", TargetID: "10", Reason: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if next.ID != old.ID+1 {
		t.Fatalf("case numbers were reused: %d after %d", next.ID, old.ID)
	}
	reopened, err := openCaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.get(old.ID); ok {
		t.Fatal("the expired case came back from disk")
	}
}
