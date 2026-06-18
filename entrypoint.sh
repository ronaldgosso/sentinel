#!/bin/sh
set -e

# Pass arguments to sentinel
if [ "$1" = "scan" ] || [ "$1" = "init" ] || [ "$1" = "update-db" ]; then
    exec sentinel "$@"
else
    # Default: run scan
    exec sentinel scan "$@"
fi
