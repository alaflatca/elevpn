//go:build mage

package main

import (
	"fmt"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const appName = "elevpn"
const binDir = "bin"

var Default = Build

func Build() error {
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}

	out := fmt.Sprintf("%s/%s", binDir, appName)
	return sh.RunV("go", "build", "-o", out, ".")
}

func Server() error {
	mg.Deps(Build)

	app := fmt.Sprintf("%s/%s", binDir, appName)
	return sh.RunV("sudo", app, "server")
}

func Client() error {
	mg.Deps(Build)

	app := fmt.Sprintf("%s/%s", binDir, appName)
	return sh.RunV("sudo", app, "client", "--server", "127.0.0.1:9010")
}

func Clean() error {
	return sh.Rm(binDir)
}
