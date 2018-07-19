import pytest

import ledger_validator
from ledger_validator import run


def test_ledger_basic(capsys):
    run(['test/resources/files'],
        True,
        'test/resources/eValidate_ledger.json',
        'test/resources/eValidate-public.key')
    captured = capsys.readouterr()
    assert captured.err == ''
    lines = captured.out.splitlines()
    sorted_lines = sorted(lines)
    with open('test/resources/expected_a.txt') as fin:
        expected = fin.read()
    expected_lines = expected.splitlines()
    assert sorted_lines == expected_lines


@pytest.mark.xfail  # TODO: Missing input should be an error
def test_ledger_missing_input():
    with pytest.raises(ValueError):
        run(['test/resources/missing'],
            True,
            'test/resources/eValidate_ledger.json',
            'test/resources/eValidate-public.key')


def test_ledger_bad_ledger():
    with pytest.raises(ValueError):
        run(['test/resources/files'],
            True,
            'test/resources/bad-ledger-a.json',
            'test/resources/eValidate-public.key')


def test_ledger_bad_key():
    with pytest.raises(Exception):
        run(['test/resources/files'],
            True,
            'test/resources/eValidate_ledger.json',
            'test/resources/bad-key.key')


def test_read_ledger():
    ledger_validator.RECORDS = None
    ledger_validator.RECORDS_BY_HASH = {}
    ledger_validator.read_ledger('test/resources/eValidate_ledger_00.json')
    EXEPECTED_RECORDS = [
        {
            u'previousblockhash': u'',
            u'localid': u'smpid_0',
            u'filehash': u'n0Od+EuQKQX9pp2w4jCOhyUixW9z+NLDVa14220cPTkYkojRc82'
                         u'tgcRTOfF+P9qbQpnLRIMjTNlNBKD+A5XGtQ==',
            u'blockindex': 0,
            u'filesignature': u'CVzfsk4X6Uy8uRiOwcgHWE1ouaa7+1XxLb3s3xWR2MCEMj'
                              u'3h/uuIs8ueADBSZ+gPheEFHuV9ESvikMI96TWR80MiotYc'
                              u'S2AYOpJO7x2VWT0SAa95YEPimShLgPyRXGf44JZPXha/s'
                              u'/0ySI5LePqHuz54l+0ThYHDkQz87irEc1Y=',
            u'blocktimestamp': 1530889311.415133,
            u'patientid': u'22651339',
            u'rptid': u'rptid_100002',
            u'rpttype': u'xml',
            u'rptdate': 1064739376262
        }
    ]
    assert ledger_validator.RECORDS == EXEPECTED_RECORDS
    block = EXEPECTED_RECORDS[0]
    assert ledger_validator.RECORDS_BY_HASH == {
        block[u'filehash']: block
    }
