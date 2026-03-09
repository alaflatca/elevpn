package tun

import (
	"os"
)

type Device struct {
	File *os.File
	Name string
}

func (d *Device) Close() error {
	if d == nil || d.File == nil {
		return nil
	}
	return d.File.Close()
}
