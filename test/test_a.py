import sys

from ledger_validator import run


def test_1():
    assert 2 + 2 == 4, 'bleh'


def test_ledger_missing():
    run('test/resources/missing',
        True,
        'test/resources/bad-ledger-missing.json',
        'test/resources/bad-key.key')


def test_all_bad():
    run('test/resources/missing',
        True,
        'test/resources/bad-ledger-a.json',
        'test/resources/bad-key.key')
