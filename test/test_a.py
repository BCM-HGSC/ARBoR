import pytest

from ledger_validator import run


def test_ledger_basic():
    run(['test/resources/files'],
        True,
        'test/resources/eValidate_ledger.json',
        'test/resources/eValidate-public.key')


@pytest.mark.xfail  # Missing input should be an error
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
