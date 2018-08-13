"""Code for dealing with a blockchain in memory."""

from __future__ import unicode_literals
from base64 import b64encode, b64decode
from functools import partial
import json  # import yaml # http://pyyaml.org/wiki/PyYAML
import time

import Crypto.Hash.SHA512 as HASH  # pip install pycrypto


# Block size for buffering file reads.
# JJ_NOTE: Rename BLOCKSIZE to avoid confusion with file buffering and ledger
# block.
BUFFERSIZE = 65536  # 64*1024

# Field names used in ledger and ledger output.
PATIENT = 'patientid'
SAMPLE = 'localid'
RPTID = 'rptid'
RPTDATE = 'rptdate'
FILEPATH = 'filepath'
FILEHASH = 'filehash'
REPORTTYPE = 'rpttype'
BLOCKINDEX = 'blockindex'
BLOCKTIMESTAMP = 'blocktimestamp'
PREVBLOCKHASH = 'previousblockhash'
BLOCKHASH = 'blockhash'
BLOCKSIG = 'blocksignature'

BLOCK_DATA_KEYS = set((
    BLOCKINDEX,
    BLOCKTIMESTAMP,
    FILEHASH,
    SAMPLE,
    PATIENT,
    PREVBLOCKHASH,
    RPTDATE,
    RPTID,
    REPORTTYPE
))

# Globals used in reading/verifying ledger
_blockchain = None


def get_blockchain():
    global _blockchain
    if _blockchain is None:
        _blockchain = Blockchain()
    return _blockchain


class Blockchain(object):
    """A list of "blocks" with an index by hash."""
    def __init__(self):
        self.clear()

    def clear(self):
        self.blocks = []
        self.by_hash = {}


def hash_files(records):
    '''Generate hash, signature, for file associated with each record, store
    in ledger record.'''
    for record in records:
        # Create a hash object from the file.
        filepath = record[FILEPATH]
        filehash = get_file_hash(filepath)
        # Store the checksum.
        record[FILEHASH] = b64encode(filehash.digest())
        # Note, hex is preferred for visual comparisons.
    return


####################
# Blockchain Utils #
####################

def append_block(chain, signer, record):
    '''Link a new record onto the chain.'''
    # Link current block to previous block in chain.
    if len(chain) != 0:
        previous_block = chain[-1]
        record[PREVBLOCKHASH] = b64encode(hash_block(previous_block).digest())
    else:
        previous_block = genesis_block()
        record[PREVBLOCKHASH] = ''
    # Increment block index.
    record[BLOCKINDEX] = previous_block[BLOCKINDEX] + 1
    record[BLOCKTIMESTAMP] = time.time()
    # Lock block contents with a digital signature.
    sign_block(signer, record)
    # JJ_TODO: Do some validations on the record - test that it should be
    # allowed before adding onto the chain.
    # Append block to chain.
    chain.append(record)


def genesis_block():
    '''Special case for record being the very first in the blockchain.'''
    genesis_info = {BLOCKINDEX: -1}
    return genesis_info


def sign_block(signer, block):
    '''Create a digital signature of the block contents and add into block.
    This must be the very last step.'''
    blockhash = hash_block(block)
    # Generate a digital signature for the block.
    signature = b64encode(signer.sign(blockhash))
    block[BLOCKSIG] = signature
    return block


def hash_block(block):
    '''Generate hash object of the block contents, excluding the signature.'''
    if BLOCKSIG in block:
        block = dict(block)
        del block[BLOCKSIG]
    assert set(block) == BLOCK_DATA_KEYS, set(block) ^ BLOCK_DATA_KEYS
    data = get_record_dump(block).encode('ascii')
    return HASH.new(data)


def get_record_dump(record):
    '''Returns a single digestible string of dictionary contents.'''
    # NOTE: JSON with sorted keys provides is a very universal spec.
    return dumps(record, sort_keys=True)


def verify_file(filehash):
    '''Verify contents of file have not been tampered with.
    Returns True if file can be matched by digital signature against a ledger
    record.'''
    rec = get_record_by_hash(filehash)
    if rec:
        # JJ_TODO: Do we need to verify digital signatures in the
        #          ledger-generation phase? Would it even be possible to
        #          determine if the file has been tampered with on DNANexus?
        #          I suspect not, and a modified file would be picked up as a
        #          completely new file and added to the ledger.
        return True
    else:
        return False


def get_record_by_hash(filehash):
    '''Find and return the ledger record created with a matching hash.'''
    digest = b64encode(filehash.digest())
    record = get_blockchain().by_hash.get(digest)
    return record


def get_file_hash(filepath):
    '''Create and return a hash object populated with the contents of the file
    at filepath.'''
    filehash = HASH.new()
    with open(filepath, 'rb') as afile:
        buf = afile.read(BUFFERSIZE)
        while len(buf) > 0:
            filehash.update(buf)
            buf = afile.read(BUFFERSIZE)
    return filehash


def is_already_in_ledger(filepath):
    '''Returns True if file has already been included in the ledger.'''
    filehash = get_file_hash(filepath)
    is_in_ledger = verify_file(filehash)
    return is_in_ledger


class ASCIIBytesJSONEncoder(json.JSONEncoder):
    '''Extends normal encode to convert'''
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode('ascii')
        else:
            return JSONEncoder.default(self, o)


dump = partial(json.dump, cls=ASCIIBytesJSONEncoder)
dumps = partial(json.dumps, cls=ASCIIBytesJSONEncoder)
