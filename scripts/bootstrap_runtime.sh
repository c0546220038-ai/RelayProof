#!/bin/sh
set -eu

python -m pip install \
    --require-hashes \
    --only-binary=:all: \
    -r runtime-requirements.lock
