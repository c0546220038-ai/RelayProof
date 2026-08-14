#!/bin/sh
set -eu

python -m pip install \
    --require-hashes \
    --only-binary=:all: \
    -r build-requirements.lock
python -m pip wheel \
    --no-build-isolation \
    --no-deps \
    --wheel-dir dist \
    .
