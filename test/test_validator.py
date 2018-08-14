from base64 import b64encode

import py
import pytest

import arbor
from arbor.blockchain import get_blockchain
import ledger_validator
from ledger_validator import run
from resources import BLOCK_0


RESOURCE_BASE = py.path.local('test/resources')


def test_ledger_basic(capsys):
    returncode = run(['test/resources/files'],
                     True,
                     'test/resources/arbor-ledger.json',
                     'test/resources/arbor-public.key')
    captured = capsys.readouterr()
    assert captured.err == ''
    lines = captured.out.splitlines()
    sorted_lines = sorted(lines)
    with open('test/resources/expected_a.txt') as fin:
        expected = fin.read()
    expected_lines = expected.splitlines()
    assert sorted_lines == expected_lines
    assert returncode == 0


def test_ledger_two_files(capsys):
    assert RESOURCE_BASE.check(dir=1)
    src1 = RESOURCE_BASE.join('files/rpt_test-100000.pdf')
    src2 = RESOURCE_BASE.join('files/rpt_test-100001.pdf')
    assert src1.check(file=1)
    assert src2.check(file=1)
    run([str(src1), str(src2)],
        True,
        'test/resources/arbor-ledger.json',
        'test/resources/arbor-public.key')
    captured = capsys.readouterr()
    assert captured.err == ''
    lines = captured.out.splitlines()
    sorted_lines = sorted(lines)
    print(sorted_lines)
    assert len(lines) == 2


def test_ledger_duplicate_file(tmpdir, capsys):
    assert RESOURCE_BASE.check(dir=1)
    src1 = RESOURCE_BASE.join('files/rpt_test-100000.pdf')
    src2 = tmpdir.join('rpt.pdf')
    assert not src2.check()
    src1.copy(src2)
    assert src1.check(file=1)
    assert src2.check(file=1)
    run([str(src1), str(src2)],
        True,
        'test/resources/arbor-ledger.json',
        'test/resources/arbor-public.key')
    captured = capsys.readouterr()
    assert captured.err == ''
    lines = captured.out.splitlines()
    sorted_lines = sorted(lines)
    print(sorted_lines)
    assert len(lines) == 2


@pytest.mark.xfail  # TODO: Missing input should be an error
def test_ledger_missing_input():
    with pytest.raises(ValueError):
        run(['test/resources/missing'],
            True,
            'test/resources/arbor-ledger.json',
            'test/resources/arbor-public.key')


def test_ledger_bad_ledger():
    with pytest.raises(ValueError):
        run(['test/resources/files'],
            True,
            'test/resources/bad-ledger-a.json',
            'test/resources/arbor-public.key')


def test_ledger_bad_key():
    with pytest.raises(Exception):
        run(['test/resources/files'],
            True,
            'test/resources/arbor-ledger.json',
            'test/resources/bad-key.key')


def test_read_ledger():
    blockchain = get_blockchain()
    blockchain.clear()
    ledger_validator.read_ledger('test/resources/arbor-ledger-00.json')
    assert blockchain.blocks == [BLOCK_0]
    block = BLOCK_0
    assert blockchain.by_hash == {
        BLOCK_0[u'filehash']: BLOCK_0
    }


def test_clean_path():
    result = ledger_validator.clean_path('test/resources/files')
    assert result == 'test/resources/files/'


def test_is_match():
    assert ledger_validator.is_match(
        'test/resources/files/rpt_test-100000.pdf',
        ['*.xml','*.pdf']
    ) == True
    assert bool (ledger_validator.is_match(
        'test/resources/files/rpt_test-100000.pdf',
        ['*.xml','*.txt']
    )) == False  # TODO: Function relies on the falsiness of None


def test_get_file_hash():
    file_hash = ledger_validator.get_file_hash(
        'test/resources/files/rpt_test-100000.pdf'
    )
    file_digest = b64encode(file_hash.digest())
    expected = (b'Hwh+kaKZ/sqhcL4KBo0gXoiWUw9P1TsuQfUBEu8bdADFBWBJCJWw2Rcdu3L'
                b'OxCOCbM6N3p/xFhvzzpBbV2d+uA==')
    assert file_digest == expected


def test_ledger_no_files(capsys):
    returncode = run([],
                     True,
                     'test/resources/arbor-ledger.json',
                     'test/resources/arbor-public.key')
    captured = capsys.readouterr()
    assert captured.err == ''
    assert captured.out == ''
    assert returncode == 0


@pytest.mark.xfail  # TODO: implement after we have a spec on this
def test_detect_broken_link(capsys):
    returncode = run(['test/resources/files'],
                      True,
                      'test/resources/bad-ledger-b.json',
                      'test/resources/arbor-public.key')
    captured = capsys.readouterr()
    assert captured.err == 'block 8 has bad link\n'
    assert captured.out == 'BLOCKCHAIN_ERROR\n'
    assert returncode == 2


@pytest.mark.xfail  # TODO: implement after we have a spec on this
def test_detect_bad_signature(capsys):
    returncode = run(['test/resources/files'],
                      True,
                      'test/resources/bad-ledger-c.json',
                      'test/resources/arbor-public.key')
    captured = capsys.readouterr()
    assert captured.err == 'block 8 has bad signature\n'
    assert captured.out == 'BLOCKCHAIN_ERROR\n'
    assert returncode == 3


@pytest.mark.xfail  # TODO: implement after we have a spec on this
def test_detect_bad_key(capsys):
    returncode = run(['test/resources/files'],
                      True,
                      'test/resources/arbor-ledger.json',
                      'test/resources/arbor-bad-public.key')
    captured = capsys.readouterr()
    assert captured.err == 'block 9 has bad signature\n'
    assert captured.out == 'BLOCKCHAIN_ERROR\n'
    assert returncode == 3
