// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

// Command generate-trust-policy-schema writes the public trust policy schema bundle.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/truster-dev/truster/v2/trustpolicy"
)

const schemaPath = "trust-policy.schema.json"

// main generates schemas or verifies that committed schemas are current.
func main() {
	check := flag.Bool("check", false, "verify generated schemas without writing files")
	output := flag.String("output", "schema/v2", "schema output directory")
	flag.Parse()

	data, err := trustpolicy.JSONSchema()
	if err != nil {
		fail(err)
	}
	path := filepath.Join(*output, schemaPath)
	if *check {
		committed, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(committed, data) {
			fail(fmt.Errorf("%s is out of date; run make schemas", path))
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fail(fmt.Errorf("write %s: %w", path, err))
	}
}

// fail reports a generation failure and exits nonzero.
func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
