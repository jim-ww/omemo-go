package memstore

import (
	"context"
	"testing"

	omemo "github.com/jim-ww/omemo-go"
)

// TestNextPreKeyIDSurvivesConsumption guards against a real bug: deriving the
// next prekey ID from PreKeyCount (the live, unconsumed count) instead of a
// dedicated watermark. Once some prekeys are consumed, PreKeyCount drops
// below the true ID high-water mark, so count-based allocation mints IDs
// that collide with still-unconsumed ones and silently overwrites them.
func TestNextPreKeyIDSurvivesConsumption(t *testing.T) {
	ctx := context.Background()
	s := New()

	// Allocate and store 10 prekeys, IDs 1..10.
	var first []omemo.PreKeyRecord
	for i := 0; i < 10; i++ {
		id, err := s.NextPreKeyID(ctx)
		if err != nil {
			t.Fatal(err)
		}
		first = append(first, omemo.PreKeyRecord{ID: id, Public: []byte{byte(id)}, Private: []byte{byte(id)}})
	}
	if err := s.PutPreKeys(ctx, first); err != nil {
		t.Fatal(err)
	}

	// Consume most of them, leaving only ID 10 unconsumed.
	for i := uint32(1); i <= 9; i++ {
		if _, err := s.ConsumePreKey(ctx, i); err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
	}
	count, err := s.PreKeyCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 unconsumed prekey, got %d", count)
	}

	// Now generate 5 more. A count-based scheme would start at count+1 = 2,
	// immediately colliding with and overwriting the still-unconsumed ID 10
	// once it wrapped around, or worse, id 2 directly is free here - use a
	// case that actually collides: allocate one more and confirm it does NOT
	// reuse ID 10.
	newID, err := s.NextPreKeyID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if newID == 10 {
		t.Fatalf("new prekey ID %d collides with still-unconsumed ID 10", newID)
	}
	if err := s.PutPreKeys(ctx, []omemo.PreKeyRecord{{ID: newID, Public: []byte{99}, Private: []byte{99}}}); err != nil {
		t.Fatal(err)
	}

	// ID 10's original key material must be untouched.
	recs, err := s.PreKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recs {
		if r.ID == 10 {
			found = true
			if r.Public[0] != 10 {
				t.Fatalf("prekey ID 10 was overwritten: got public key %v", r.Public)
			}
		}
	}
	if !found {
		t.Fatal("prekey ID 10 is missing")
	}
}
