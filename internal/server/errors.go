package server

import "errors"

var (
	ErrDropPacket   = errors.New("drop packet")
	ErrReplayPacket = errors.New("replay packet")
)
