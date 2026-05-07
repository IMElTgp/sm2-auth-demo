#!/usr/bin/env bash
set -euo pipefail

go test -v ./internal/gui -count=1
go test -v ./tests -count=1

