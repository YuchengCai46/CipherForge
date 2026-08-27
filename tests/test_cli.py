import base64
import os

import pytest

from cli import build_parser, main


@pytest.fixture
def workdir(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    (d / "plain.txt").write_bytes(b"CLI test payload 12345")
    return d


def test_cli_encrypt_decrypt(workdir, monkeypatch):
    monkeypatch.chdir(workdir)
    rc = main(["encrypt", "--algo", "AES-256-GCM", "--password", "pw",
               "--in", "plain.txt", "--out", "enc.bin"])
    assert rc == 0
    rc = main(["decrypt", "--algo", "AES-256-GCM", "--password", "pw",
               "--in", "enc.bin", "--out", "dec.txt"])
    assert rc == 0
    assert (workdir / "dec.txt").read_bytes() == (workdir / "plain.txt").read_bytes()


def test_cli_hash(workdir, monkeypatch, capsys):
    monkeypatch.chdir(workdir)
    rc = main(["hash", "--algo", "SHA-256", "--in", "plain.txt"])
    assert rc == 0
    out = capsys.readouterr().out
    assert len(out.strip()) == 64


def test_cli_passgen(workdir, monkeypatch, capsys):
    monkeypatch.chdir(workdir)
    rc = main(["passgen", "--length", "20"])
    assert rc == 0
    out = capsys.readouterr().out
    assert len(out.splitlines()[0]) == 20


def test_cli_shamir(workdir, monkeypatch):
    monkeypatch.chdir(workdir)
    rc = main(["shamir-split", "--threshold", "2", "--total", "3",
               "--in", "plain.txt", "--out-dir", "shares"])
    assert rc == 0
    rc = main(["shamir-combine", "--shares", "shares/share_*.txt",
               "--out", "rec.txt", "--threshold", "2"])
    assert rc == 0
    assert (workdir / "rec.txt").read_bytes() == (workdir / "plain.txt").read_bytes()


def test_cli_cascade(workdir, monkeypatch):
    monkeypatch.chdir(workdir)
    rc = main(["cascade-encrypt", "--layers", "AES-256-GCM,ChaCha20-Poly1305",
               "--password", "p", "--in", "plain.txt", "--out", "c.bin"])
    assert rc == 0
    rc = main(["cascade-decrypt", "--layers", "AES-256-GCM,ChaCha20-Poly1305",
               "--password", "p", "--in", "c.bin", "--out", "cd.txt"])
    assert rc == 0
    assert (workdir / "cd.txt").read_bytes() == (workdir / "plain.txt").read_bytes()


def test_cli_help_exits():
    with pytest.raises(SystemExit):
        main(["--help"])
