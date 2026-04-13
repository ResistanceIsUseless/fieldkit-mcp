#!/usr/bin/env python3
"""Backward-compatible wrapper for the renamed server module."""

from fieldkit_mcp_server import *  # noqa: F401,F403


if __name__ == "__main__":
    import runpy

    runpy.run_module("fieldkit_mcp_server", run_name="__main__")
