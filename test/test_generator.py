from __future__ import unicode_literals
from base64 import b64encode

import pytest

from ledger_generator import run as generate
from ledger_validator import run as validate


def test_ledger_roundtrip(tmpdir, capsys):
    """Functional test"""
    ledger_path = str(tmpdir.join('arbor-ledger-test.json'))
    private_key_path = 'test/resources/arbor-private.key'
    public_key_path = 'test/resources/arbor-public.key'
    input_paths = ['test/resources/files/']
    generate(input_paths, True, ledger_path, private_key_path, public_key_path)
    captured = capsys.readouterr()
    assert captured.err == ''
    assert captured.out == 'Generating Ledger\nDone\n'
    validate(input_paths, True, ledger_path, public_key_path)
    captured = capsys.readouterr()
    assert captured.err == ''
    lines = captured.out.splitlines()
    sorted_lines = sorted(lines)
    with open('test/resources/expected_b.txt', 'rb') as fin:
        expected = fin.read()
    expected_lines = [l.decode('ascii') for l in expected.splitlines()]
    assert sorted_lines == expected_lines
