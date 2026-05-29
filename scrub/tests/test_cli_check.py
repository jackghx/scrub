"""Tests for ``scrub --check``, the detection/scan mode the git hook relies on.

Exit code is the mechanism: 1 if a secret is found, 0 if clean. The report must be
masked so the scan itself never leaks secrets to scrollback.
"""

import io

import pytest

from cli import main, mask

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def test_check_finds_secret_exits_1(capsys, tmp_path):
    f = tmp_path / "config.env"
    f.write_text(f"line one\naws_access_key_id={FAKE_AWS_KEY}\n", encoding="utf-8")
    rc = main(["--check", str(f)])
    captured = capsys.readouterr()
    assert rc == 1
    # report goes to stderr, never stdout
    assert captured.out == ""
    assert "AWS_ACCESS_KEY" in captured.err
    # line number reported (the key is on line 2)
    assert ":2" in captured.err


def test_check_report_is_masked(capsys, tmp_path):
    f = tmp_path / "config.env"
    f.write_text(f"aws_access_key_id={FAKE_AWS_KEY}\n", encoding="utf-8")
    main(["--check", str(f)])
    err = capsys.readouterr().err
    # the raw secret must NOT appear; the masked form must
    assert FAKE_AWS_KEY not in err
    assert mask(FAKE_AWS_KEY) in err


def test_check_clean_file_exits_0(capsys, tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("the quick brown fox jumps over the lazy dog\n", encoding="utf-8")
    rc = main(["--check", str(f)])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == ""
    assert captured.err == ""


def test_check_stdin_with_label(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(f"key={FAKE_AWS_KEY}\n"))
    rc = main(["--check", "--label", "staged:secrets.env", "-"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "staged:secrets.env:1" in err


def test_check_threshold_changes_outcome(capsys, tmp_path):
    # a bare internal IP scores 0.85 (>= 0.6) -> flagged by default
    f = tmp_path / "n.txt"
    f.write_text("gateway 10.10.10.1\n", encoding="utf-8")

    assert main(["--check", str(f)]) == 1
    capsys.readouterr()

    # raise the threshold above the IP score -> clean
    assert main(["--check", str(f), "--threshold", "0.95"]) == 0
    capsys.readouterr()


def test_check_allow_suppresses_type(capsys, tmp_path):
    f = tmp_path / "n.txt"
    f.write_text("contacted 8.8.8.8 for dns\n", encoding="utf-8")  # PUBLIC_IP, score 0.6

    assert main(["--check", str(f)]) == 1
    capsys.readouterr()

    assert main(["--check", str(f), "--allow", "PUBLIC_IP"]) == 0
    capsys.readouterr()


def test_allow_rejected_outside_check(capsys, tmp_path):
    f = tmp_path / "n.txt"
    f.write_text("gateway 10.10.10.1\n", encoding="utf-8")
    rc = main([str(f), "--allow", "PUBLIC_IP"])
    assert rc == 2
    assert "--allow only applies to --check" in capsys.readouterr().err


def test_check_blocks_context_aws_secret_at_default(capsys, tmp_path):
    # Regression for the diagnosed gap: in custom-only mode the AWS secret key with its
    # trigger words must now be lifted over the 0.6 default and BLOCK the commit hook.
    f = tmp_path / "creds.env"
    f.write_text(
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        encoding="utf-8",
    )
    rc = main(["--check", str(f)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "AWS_SECRET_KEY" in err
    # masked, the raw secret never reaches the report
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in err


def test_check_bare_blob_without_context_does_not_block(capsys, tmp_path):
    # The false-positive guard: a bare 40-char blob with no trigger words nearby must
    # NOT block (stays at base 0.35, below the 0.6 default) -> exit 0.
    f = tmp_path / "data.txt"
    f.write_text(
        "the quick brown fox wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY lazy dog\n",
        encoding="utf-8",
    )
    rc = main(["--check", str(f)])
    assert rc == 0  # not blocked


def test_check_subthreshold_passes_with_masked_near_miss_notice(capsys, tmp_path):
    # Sub-threshold-only file: passes (exit 0) but the near-miss notice surfaces it.
    blob = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    f = tmp_path / "data.txt"
    f.write_text(f"the quick brown fox {blob} lazy dog\n", encoding="utf-8")
    rc = main(["--check", str(f)])
    captured = capsys.readouterr()
    assert rc == 0  # never blocks
    assert captured.out == ""  # notice goes to stderr, not stdout
    assert "NOT blocked" in captured.err
    assert "AWS_SECRET_KEY" in captured.err
    assert blob not in captured.err  # masked


def test_check_fully_clean_prints_no_notice(capsys, tmp_path):
    # No detections at all -> exit 0 and complete silence (no new noise).
    f = tmp_path / "clean.txt"
    f.write_text("the quick brown fox jumps over the lazy dog\n", encoding="utf-8")
    rc = main(["--check", str(f)])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.err == ""


def test_check_blocking_does_not_append_near_miss(capsys, tmp_path):
    # A file with BOTH a blocking secret and a sub-threshold detection: one clear
    # message, the blocking report only, no near-miss note appended.
    f = tmp_path / "mix.txt"
    f.write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nplease visit db.internal today\n",
        encoding="utf-8",
    )
    rc = main(["--check", str(f)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "possible secret" in err  # blocking report present
    assert "note:" not in err  # near-miss note NOT appended in the blocking path
    assert "NOT blocked" not in err


def test_no_near_miss_suppresses_notice_keeps_exit0(capsys, tmp_path):
    blob = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    f = tmp_path / "data.txt"
    f.write_text(f"random {blob} text\n", encoding="utf-8")
    rc = main(["--check", "--no-near-miss", str(f)])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.err == ""  # notice suppressed


def test_no_near_miss_preserves_blocking_exit1(capsys, tmp_path):
    # The opt-out never changes blocking behaviour.
    f = tmp_path / "creds.env"
    f.write_text(
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        encoding="utf-8",
    )
    rc = main(["--check", "--no-near-miss", str(f)])
    assert rc == 1


@pytest.mark.parametrize(
    "value",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "short",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_mask_never_contains_full_secret(value):
    masked = mask(value)
    # the full secret is never reproduced verbatim in the masked form
    assert value not in masked
    assert "•" in masked or masked.endswith("multi-line)")
