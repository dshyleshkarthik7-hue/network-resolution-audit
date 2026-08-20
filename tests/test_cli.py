"""Tests for the CLI module."""

import contextlib

from network_resolution_audit.cli import main


def test_main_runs() -> None:
    """Test that main function can be called."""
    with contextlib.suppress(SystemExit):
        main()
