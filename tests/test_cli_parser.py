"""Tests for the CLI argument parser, ensuring new flags are recognized.

This focuses on the `serve` subcommand and verifies that the recently added
`--no-access-log` flag exists, defaults to ``False`` and parses to ``True`` when
specified.
"""



def test_build_parser_includes_no_access_log_flag():
    from warden.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["serve", "--no-access-log"])
    # The flag should be parsed as True
    assert args.no_access_log is True
    # Without the flag it should be False (default)
    args_no = parser.parse_args(["serve"])
    assert args_no.no_access_log is False
