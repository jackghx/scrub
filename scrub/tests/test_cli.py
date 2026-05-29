"""Tests for the Scrub CLI, transform and restore modes.

These drive ``cli.main([...])`` directly and capture stdout/stderr with ``capsys``,
so they need no editable install and no spaCy model (custom-only mode). Imports are
flat via conftest, like the rest of the suite.
"""

import io
import json
import os

import pytest

from cli import _Style, _render_table, main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "sample.log")


def _sample_text():
    with open(SAMPLE, encoding="utf-8", newline="") as fh:
        return fh.read()


def test_transform_file_to_stdout(capsys):
    rc = main([SAMPLE])
    out = capsys.readouterr().out
    assert rc == 0
    # high-confidence secrets are replaced by placeholders...
    assert "<INTERNAL_IP_1>" in out
    assert "<AWS_ACCESS_KEY_1>" in out
    # ...and their raw values are gone.
    assert "10.10.10.1" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_transform_stdin_to_stdout(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("gateway 10.10.10.1 again 10.10.10.1\n"))
    rc = main([])  # no file arg => read stdin
    out = capsys.readouterr().out
    assert rc == 0
    assert out == "gateway <INTERNAL_IP_1> again <INTERNAL_IP_1>\n"


def test_threshold_zero_scrubs_low_confidence(capsys):
    # AWS secret key scores 0.35, left in the clear at the default 0.6, scrubbed at 0.
    rc = main([SAMPLE, "--threshold", "0"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out
    assert "<AWS_SECRET_KEY_1>" in out


def test_context_lifts_aws_secret_at_default(capsys):
    # The sample line `aws_secret_access_key = wJalr...` carries its trigger words, so
    # the spaCy-free context enhancer lifts AWS_SECRET_KEY (0.35 -> 0.70) over the 0.6
    # default and it IS scrubbed in custom-only mode.
    rc = main([SAMPLE])  # default 0.6
    out = capsys.readouterr().out
    assert rc == 0
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out
    assert "<AWS_SECRET_KEY_1>" in out


def test_context_less_blob_passes_but_is_surfaced(capsys, tmp_path):
    # A bare 40-char blob with NO trigger words nearby stays at base 0.35 (the FP
    # guard): it is NOT scrubbed at the 0.6 default...
    blob = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    f = tmp_path / "data.txt"
    f.write_text(f"the quick brown fox jumps {blob} over the lazy dog\n", encoding="utf-8")
    rc = main([str(f)])
    captured = capsys.readouterr()
    assert rc == 0
    assert blob in captured.out  # passed through (low confidence)
    # ...but option B surfaces it on stderr rather than silently dropping it.
    assert "NOT applied" in captured.err
    assert "AWS_SECRET_KEY" in captured.err
    assert blob not in captured.err  # the summary is masked


def test_subthreshold_summary_silent_at_threshold_zero(capsys, tmp_path):
    blob = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    f = tmp_path / "data.txt"
    f.write_text(f"random {blob} text\n", encoding="utf-8")
    rc = main([str(f), "--threshold", "0"])
    captured = capsys.readouterr()
    assert rc == 0
    assert blob not in captured.out  # scrubbed at 0
    assert "NOT applied" not in captured.err  # nothing is below threshold 0


def test_mapping_written_only_when_requested(capsys, tmp_path):
    map_path = tmp_path / "m.json"
    rc = main([SAMPLE, "--mapping", str(map_path)])
    out = capsys.readouterr().out
    assert rc == 0
    # the mapping file holds the real secrets...
    data = json.loads(map_path.read_text(encoding="utf-8"))
    assert "10.10.10.1" in data.values()
    # ...but nothing secret leaked to stdout.
    assert "10.10.10.1" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_no_mapping_file_without_flag(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main([SAMPLE])
    assert rc == 0
    # no stray mapping artefacts created
    assert list(tmp_path.iterdir()) == []


def test_restore_round_trip_byte_for_byte(capsys, tmp_path, monkeypatch):
    original = _sample_text()
    map_path = tmp_path / "m.json"

    # transform with mapping
    main([SAMPLE, "--mapping", str(map_path)])
    scrubbed = capsys.readouterr().out

    # restore from stdin + mapping
    monkeypatch.setattr("sys.stdin", io.StringIO(scrubbed))
    rc = main(["--restore", str(map_path)])
    restored = capsys.readouterr().out
    assert rc == 0
    assert restored == original


def test_errors_go_to_stderr_not_stdout(capsys):
    rc = main(["/no/such/file.log"])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""  # stdout stays clean for pipes
    assert "scrub:" in captured.err


def test_mutually_exclusive_modes(capsys, tmp_path):
    rc = main(["--check", "--restore", str(tmp_path / "m.json")])
    captured = capsys.readouterr()
    assert rc == 2
    assert "mutually exclusive" in captured.err


def test_mapping_rejected_outside_transform(capsys, tmp_path):
    rc = main(["--check", "--mapping", str(tmp_path / "m.json"), SAMPLE])
    assert rc == 2
    assert "transform" in capsys.readouterr().err


def test_version(capsys):
    rc = main(["--version"])
    assert rc == 0
    assert capsys.readouterr().out.startswith("scrub ")


# --- usability: no-input guard, colour, spinner -----------------------------


class _TTYStringIO(io.StringIO):
    """A stdin stand-in that reports itself as an interactive terminal."""

    def isatty(self) -> bool:
        return True


def test_bare_command_with_tty_stdin_exits_2(capsys, monkeypatch):
    # No file and an interactive terminal must NOT block on stdin: print usage,
    # exit 2 (conventional usage error), and keep stdout clean.
    monkeypatch.setattr("sys.stdin", _TTYStringIO(""))
    rc = main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert "usage" in captured.err.lower()
    assert "--help" in captured.err


def test_check_bare_with_tty_stdin_exits_2(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", _TTYStringIO(""))
    rc = main(["--check"])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""


def test_piped_stdin_still_scrubs(capsys, monkeypatch):
    # Non-TTY stdin (something piped in) keeps the original behaviour.
    monkeypatch.setattr("sys.stdin", io.StringIO("gateway 10.10.10.1\n"))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert out == "gateway <INTERNAL_IP_1>\n"


def test_check_report_has_no_ansi_when_not_tty(capsys, tmp_path):
    # Under capture, stderr is not a TTY, so the report must be plain.
    f = tmp_path / "c.env"
    f.write_text("aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    main(["--check", str(f)])
    captured = capsys.readouterr()
    assert "\x1b[" not in captured.err
    assert "\x1b[" not in captured.out


def test_no_color_flag_suppresses_ansi(capsys, tmp_path):
    f = tmp_path / "c.env"
    f.write_text("aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    main(["--check", "--no-color", str(f)])
    captured = capsys.readouterr()
    assert "\x1b[" not in captured.err
    assert "\x1b[" not in captured.out


def test_stdout_stays_plain_across_flags(capsys):
    # stdout is sacred: never ANSI, never spinner carriage-returns, under any flag.
    for argv in (
        [SAMPLE],
        [SAMPLE, "--no-color"],
        [SAMPLE, "--quiet"],
        [SAMPLE, "--threshold", "0"],
    ):
        rc = main(argv)
        out = capsys.readouterr().out
        assert rc == 0
        assert "\x1b[" not in out
        assert "\r" not in out


def test_quiet_and_non_tty_suppress_spinner(capsys):
    rc = main([SAMPLE, "--quiet"])
    captured = capsys.readouterr()
    assert rc == 0
    # No spinner control characters or escapes leak into the captured report.
    assert "\r" not in captured.err
    assert "\x1b[" not in captured.err


def test_style_disabled_is_identity():
    s = _Style(False)
    assert s.entity("AWS") == "AWS"
    assert s.alert("blocked") == "blocked"


def test_style_enabled_wraps_in_ansi():
    s = _Style(True)
    out = s.entity("AWS")
    assert out.startswith("\x1b[")
    assert out.endswith("\x1b[0m")
    assert "AWS" in out


def test_render_table_aligns_on_plain_text():
    s = _Style(False)
    rows = [
        ("AWS_ACCESS_KEY", "AKIA****MPLE", "score=0.85", "f:2"),
        ("IP", "10.*.1", "score=0.90", "f:5"),
    ]
    lines = _render_table(rows, s)
    # The masked-value column starts at the same offset on every row.
    assert lines[0].index("AKIA") == lines[1].index("10.")
