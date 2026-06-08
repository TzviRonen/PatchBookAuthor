#!/bin/bash
set -e

mkdir -p /data/binaries /data/diffs /data/blogs /data/db

exec python -m pipeline.main "$@"
