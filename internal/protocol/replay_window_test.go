package protocol

import (
	"errors"
	"testing"
)

func TestReplayWindowRejectsZeroSequence(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(0)
	if err == nil {
		t.Fatal("expected zero sequence to be rejected")
	}
	if !errors.Is(err, ErrInvalidSequence) {
		t.Fatalf("expected ErrInvalidSequence, got: %v", err)
	}
}

func TestReplayWindowAcceptsFirstSequence(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(1)
	if err != nil {
		t.Fatalf("expected first sequence to be accepted, got: %v", err)
	}
}

func TestReplayWindowAcceptsIncreasingSequences(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(10)
	if err != nil {
		t.Fatalf("expected initial sequence to be accepted: sequence=10: %v", err)
	}

	sequences := []uint64{11, 12, 13}
	for _, seq := range sequences {
		err = rw.Accept(seq)
		if err != nil {
			t.Fatalf("expected increasing sequence to be accepted: sequence=%d: %v", seq, err)
		}
	}

	if rw.bitmap != 0b1111 {
		t.Fatalf("unexpected replay window bitmap: expected=%04b actual=%04b", uint64(0b1111), rw.bitmap)
	}
}

func TestReplayWindowAcceptsOutOfOrderSequences(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(10)
	if err != nil {
		t.Fatalf("expected initial sequence to be accepted: sequence=10: %v", err)
	}

	sequences := []uint64{9, 8, 7}
	for _, seq := range sequences {
		err := rw.Accept(seq)
		if err != nil {
			t.Fatalf("expected out-of-order sequence to be accepted: sequence=%d: %v", seq, err)
		}
	}

	if rw.bitmap != 0b1111 {
		t.Fatalf("unexpected replay window bitmap: expected=%04b actual=%04b", uint64(0b1111), rw.bitmap)
	}
}

func TestReplayWindowRejectsDuplicateSequence(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(10)
	if err != nil {
		t.Fatalf("expected initial sequence to be accepted: sequence=10: %v", err)
	}

	err = rw.Accept(10)
	if !errors.Is(err, ErrDuplicateSequence) {
		t.Fatalf("expected ErrDuplicateSequence, got: %v", err)
	}

	t.Logf("duplicate sequence rejected as expected: %v", err)
}

func TestReplayWindowRejectsTooOldSequence(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(70)
	if err != nil {
		t.Fatalf("expected initial sequence to be accepted: sequence=70: %v", err)
	}

	err = rw.Accept(6)
	if !errors.Is(err, ErrSequenceTooOld) {
		t.Fatalf("expected ErrSequenceTooOld, got: %v", err)
	}
}

func TestReplayWindowHandlesWindowBoundary(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(70)
	if err != nil {
		t.Fatalf("expected initial sequence to be accepted: sequence=70: %v", err)
	}

	err = rw.Accept(7)
	if err != nil {
		t.Fatalf("expected sequence at replay window boundary to be accepted: sequence=7 offset=63: %v", err)
	}

	expectedBitmap := uint64(1) | uint64(1)<<63
	if rw.bitmap != expectedBitmap {
		t.Fatalf("unexpected replay window bitmap: expected=%064b actual=%064b", expectedBitmap, rw.bitmap)
	}
}

func TestReplayWindowResetsAfterLargeSequenceJump(t *testing.T) {
	var rw ReplayWindow

	err := rw.Accept(70)
	if err != nil {
		t.Fatalf("expected initial sequence to be accepted: sequence=70: %v", err)
	}

	err = rw.Accept(65)
	if err != nil {
		t.Fatalf("expected out-of-order sequence to be accepted: sequence=65: %v", err)
	}

	expectedBitmapBeforeReset := uint64(1) | uint64(1)<<5
	if rw.bitmap != expectedBitmapBeforeReset {
		t.Fatalf("unexpected bitmap before replay window reset: expected=%064b actual=%064b", expectedBitmapBeforeReset, rw.bitmap)
	}

	err = rw.Accept(134)
	if err != nil {
		t.Fatalf("expected sequence after large jump to be accepted: sequence=134 offset=64: %v", err)
	}
	if rw.highest != 134 {
		t.Fatalf("unexpected highest sequence after replay window reset: expected=%d actual=%d", 134, rw.highest)
	}
	if rw.bitmap != 1 {
		t.Fatalf("unexpected bitmap after replay window reset: expected=%064b actual=%064b", uint64(1), rw.bitmap)
	}
}
