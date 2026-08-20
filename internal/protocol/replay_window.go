package protocol

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidSequence   = errors.New("invalid sequence")
	ErrSequenceTooOld    = errors.New("sequence too old")
	ErrDuplicateSequence = errors.New("duplicate sequence")
)

const replayWindowSize = 64

type ReplayWindow struct {
	highest uint64
	bitmap  uint64
}

func (rw *ReplayWindow) Accept(sequence uint64) error {
	if sequence == 0 {
		return fmt.Errorf("%w: sequence must be greater than zero", ErrInvalidSequence)
	}

	if rw.highest == 0 {
		rw.highest = sequence
		rw.bitmap = 1
		return nil
	}

	if sequence > rw.highest {
		offset := sequence - rw.highest
		if offset >= replayWindowSize {
			rw.highest = sequence
			rw.bitmap = 1
		} else {
			rw.highest = sequence
			rw.bitmap = rw.bitmap << offset
			rw.bitmap |= 1
		}
		return nil
	}

	if sequence <= rw.highest {
		offset := rw.highest - sequence // 각 시퀀스의 값들의 차
		if offset >= replayWindowSize {
			return fmt.Errorf("%w: highest=%d actual=%d", ErrSequenceTooOld, rw.highest, sequence)
		}
		mask := uint64(1) << offset // 시퀀스 값들의 차의 수 만큼 비트 연산으로, 몇 번째 비트인지 확인
		if rw.bitmap&mask != 0 {    // 이미 있는 sequence
			return fmt.Errorf("%w: sequence=%d", ErrDuplicateSequence, sequence)
		}

		rw.bitmap |= mask
	}

	return nil
}
