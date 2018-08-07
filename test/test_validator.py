from base64 import b64encode

import pytest

import arbor
from arbor.blockchain import get_blockchain
import ledger_validator
from ledger_validator import run


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
    EXEPECTED_RECORDS = [
        {
            u'previousblockhash': b'',
            u'localid': u'smpid_0',
            u'filehash': b'wg14UvdBnxg90dxMhdaquhxqUcmckemoEbtxGMWo4e6BXjFIU7h'
                         b'iiNAXDjhnmIvIYq7A08xixCS7qIEuJyDfSw==',
            u'blockindex': 0,
            u'blocksignature': b'UQks4EgJJbFTp4piYJYtNXdGXLTodo8CzUdqCPqALY9qf'
                               b'vcLaoo0tIyiiQ/ozhz5FPGbolCwmAV4OTqaz7DAB7trT1'
                               b'VVod12WMcx01x0MThfagqqqS789O4iCkbRUFvPHtLy2ki'
                               b'/plLS0XT6oDBrZYxDZL+gpWbq9Q3VzgmxZCE=',
            u'blocktimestamp': 1533071723.108952,
            u'patientid': u'22651339',
            u'rptid': u'rptid_100002',
            u'rpttype': u'xml',
            u'rptdate': 1010316094784
        }
    ]
    assert blockchain.blocks == EXEPECTED_RECORDS
    block = EXEPECTED_RECORDS[0]
    assert blockchain.by_hash == {
        block[u'filehash']: block
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
