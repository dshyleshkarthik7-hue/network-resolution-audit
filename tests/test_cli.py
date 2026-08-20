"""Tests for the CLI module."""

from network_resolution_audit.cli import main


def test_main_runs() -> None:
    """Test that main function can be called."""
    try:
        main()
    except SystemExit:
        pass
