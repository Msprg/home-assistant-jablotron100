#!/usr/bin/env python3
"""Thin wrapper for running the Jablotron API server."""

from __future__ import annotations

import sys

from jablotron_api.cli.main import main


if __name__ == "__main__":
    sys.argv = [sys.argv[0], "server", *sys.argv[1:]]
    main()

