from __future__ import print_function
from pprint import pprint as pp
from sys import stderr

import pytest

from arbor.blockchain import Block
from arbor.rsa import load_verifier
from resources import BLOCK_0


def test_good_signature(verifier):
    b = Block(BLOCK_0)
    assert b.verify_signature(verifier)


def test_bad_signature(verifier):
    b = Block(BLOCK_0)
    good = b.blocksignature
    bad = b'V' + good[1:]
    b.blocksignature = bad
    assert not b.verify_signature(verifier)

@pytest.fixture
def verifier():
    """Returns an RSA verifier"""
    return load_verifier('test/resources/arbor-public.key')
