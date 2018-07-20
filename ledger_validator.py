#!/usr/bin/python2.7

"""
Directory Ledger Validator
Version: 1.0.3.2
Author: Jordan M. Jones
"""

from __future__ import print_function
import os
import argparse
import json
import fnmatch
import sys
from base64 import b64encode, b64decode
import Crypto.Hash.SHA512 as HASH # pip install pycrypto
import Crypto.Signature.PKCS1_v1_5 as PKCS
from Crypto.PublicKey import RSA

# Default Filepath of Ledger.
DEFAULT_LEDGER_FILE = 'arbor-ledger.json'

# Default Filepath of RSA Public Key.
DEFAULT_PUBLIC_KEY_FILE = 'arbor-public.key'

# Default Patterns to Match Against Filenames when Searching for Reports.
# Note, this must be a Unix shell style pattern (see fnmatch).
DEFAULT_REPORT_FILEPATTERNS = ['*.xml','*.pdf']

# Default Method for Searching a Directory for Reports.
DEFAULT_DIRECTORY_RECURSION = True

# Field names used in ledger and ledger output.
PATIENT = 'patientid'
SAMPLE = 'localid'
RPTID = 'rptid'
RPTDATE = 'rptdate'
#FILEPATH = 'filepath'
FILEHASH = 'filehash'
FILESIG = 'filesignature'
REPORTTYPE = 'rpttype'
BLOCKINDEX = 'blockindex'
BLOCKTIMESTAMP = 'blocktimestamp'
PREVBLOCKHASH = 'previousblockhash'
BLOCKHASH = 'blockhash'
BLOCKSIG = 'blocksignature'

# Block size for buffering file reads.
BUFFERSIZE = 65536 #64*1024 # JJ_NOTE: Rename BLOCKSIZE to avoid confusion with file buffering and ledger block.
#BLOCKSIZE = 65536 #64*1024

# Globals initialized by functions.
BLOCKCHAIN = [] #JJ_NOTE: Renamed from 'RECORDS' to 'BLOCKCHAIN'.
RECORDS_BY_HASH = {}
VERIFIER = None

##########################
# Ledger File Read/Write #
##########################

def read_ledger(filepath=DEFAULT_LEDGER_FILE):
    ''' Read records from ledger file and store in global variable BLOCKCHAIN. '''
    global BLOCKCHAIN, RECORDS_BY_HASH
    with open(filepath, 'rb') as f:
        BLOCKCHAIN = [entry for entry in json.load(f)]
    for rec in BLOCKCHAIN:
        convert_field_to_binary(rec, FILEHASH)
        convert_field_to_binary(rec, FILESIG)
        convert_field_to_binary(rec, PREVBLOCKHASH)
        RECORDS_BY_HASH[rec[FILEHASH]] = rec

def convert_field_to_binary(record, field_name):
    old = record[field_name]
    new = old.encode('ascii')
    record[field_name] = new

#######################
# File/Directory Util #
#######################

def clean_path(path):
    ''' Clean up path of file or directory, ensure proper formatting.
        Warn via stderr and ignore path if it is not a file or directory. '''
    path = os.path.normpath(path)
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        return os.path.join(path,'')
    else:
        print('WARN: invalid path: %s' % path, file=sys.stderr)

def is_match(path, patterns):
    ''' Returns True if path matches any pattern in patterns. '''
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True

def get_filepath_gen(paths, filepatterns=DEFAULT_REPORT_FILEPATTERNS, recursive=DEFAULT_DIRECTORY_RECURSION):
    ''' Generator function. Yields paths to files whose names match a pattern
        in filepatterns.
        If paths contains a directory then each file within it is evaluated,
        optionally recursing through its subdirectories as well.
        NOTE, Filepatterns can only include shell-style wildcards, (see fnmatch). '''
    # Lambda expression used to prevent returning duplicates.
    seen = set()
    isvalid = lambda p: is_match(p, filepatterns) and not (p in seen or seen.add(p))
    for path in [_f for _f in paths if _f]:
        if os.path.isfile(path) and isvalid(path):
            yield path
        elif recursive:
            for root, dirs, files in os.walk(path):
                for f in files:
                    fpath = os.path.join(root, f)
                    if isvalid(fpath):
                        yield fpath
        else:
            for item in os.listdir(path):
                fpath = os.path.join(path, item)
                if os.path.isfile(fpath) and isvalid(fpath):
                    yield fpath

######################
# RSA Key Operations #
######################

def load_verifier(publickey_path):
    global VERIFIER
    if os.path.isfile(publickey_path):
        publickey = import_key(publickey_path)
        VERIFIER = PKCS.new(publickey)
    else:
        raise Exception('Public key file "%s" does not exist' % publickey_path)

def import_key(filepath=DEFAULT_PUBLIC_KEY_FILE):
    ''' Import an RSA key from a provided file. '''
    with open(filepath, 'rb') as f:
        key = RSA.importKey(f.read())
    return key

#####################
# File Verification #
#####################

def get_record_by_hash(filehash):
    ''' Find and return the ledger record created with a matching hash. '''
    global RECORDS_BY_HASH
    digest = b64encode(filehash.digest())
    record = RECORDS_BY_HASH.get(digest)
    return record

def get_file_hash(filepath):
    ''' Create and return a hash object populated with the contents of the file at filepath. '''
    filehash = HASH.new()
    with open(filepath, 'rb') as afile:
        buf = afile.read(BUFFERSIZE)
        while len(buf) > 0:
            filehash.update(buf)
            buf = afile.read(BUFFERSIZE)
    return filehash

def verify_file(filehash):
    ''' Verify contents of file have not been tampered with.
        Returns True if file can be matched by digital signature against a ledger record. '''
    rec = get_record_by_hash(filehash)
    if rec:
        sig = b64decode(rec[FILESIG])
        return VERIFIER.verify(filehash, sig)
    else:
        return False

######################
# Latest File Checks #
######################

def get_latest_info_by_smp(group_by_filetype=False):
    ''' Determine which rptid and set of hashes are from the latest report version for each sample. '''
    defaultdic = {
                  BLOCKINDEX : 0,
                  RPTID : set(),
                  FILEHASH : [],
                  FILESIG : [],
                 }
    latest_by_smp = {}
    for rec in BLOCKCHAIN:
        smp = rec[SAMPLE]
        if group_by_filetype:
            # Refine grouping to distinguish file extension.
            smp += rec[REPORTTYPE]
        index = rec[BLOCKINDEX]
        maxdic = latest_by_smp.setdefault(smp, defaultdic.copy())
        if index == maxdic[BLOCKINDEX]:
            # Same date found - supplementary file, add file hash.
            maxdic[FILEHASH].append(rec[FILEHASH])
            maxdic[FILESIG].append(rec[FILESIG])
            maxdic[RPTID].add(rec[RPTID])
        elif index > maxdic[BLOCKINDEX]:
            # Newer date found, replace old one, create new list for valid hashes.
            maxdic[BLOCKINDEX] = index
            maxdic[FILEHASH] = [rec[FILEHASH]]
            maxdic[FILESIG] = [rec[FILESIG]]
            maxdic[RPTID] = set([rec[RPTID]])
        else:
            # Older date, ignore.
            pass
    return latest_by_smp

def get_latest_hashes(group_by_filetype=False):
    ''' Get set of hash digests from the ledger associated with the latest reports of each sample. '''
    # Flatten signatures of latest rptid into a single list.
    latest_by_smp = get_latest_info_by_smp(group_by_filetype)
    listoflists = [s[FILEHASH] for s in latest_by_smp.values()]
    flattened = set([val for hashlist in listoflists for val in hashlist])
    return flattened

###############
# Main Method #
###############

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-c', '--check-latest', dest='check_latest', action='store_true', help='If this flag is present, check that file(s) represent most recent report version for their respective sample')
    parser.add_argument('-l', '--ledger', metavar='LEDGER_FILE', default=DEFAULT_LEDGER_FILE, help='Path of ledger file (default: %s)' % DEFAULT_LEDGER_FILE)
    parser.add_argument('-p', '--publickey', metavar='PUBLIC_KEY_FILE', default=DEFAULT_PUBLIC_KEY_FILE, help='Path of RSA public key file (default: %s)' % DEFAULT_PUBLIC_KEY_FILE)
    parser.add_argument('paths', nargs='+', help='One or more paths to report files and/or directories containing report files')
    args = parser.parse_args()
    run(args.paths,
        args.check_latest,
        args.ledger,
        args.publickey)

def run(paths, check_latest=False, ledger_path=DEFAULT_LEDGER_FILE, publickey_path=DEFAULT_PUBLIC_KEY_FILE):
    # Initialize.
    read_ledger(ledger_path)
    load_verifier(publickey_path)
    latest = get_latest_hashes(group_by_filetype=True) #Note: 'True' may return multiple hashes per sample.

    # Sanitize input.
    cleanpaths = [clean_path(path) for path in paths]
    filepathgen = get_filepath_gen(cleanpaths)

    # Output messages.
    valid_msg = 'Valid'
    invalid_msg = 'Not valid'
    latest_msg = 'Latest for %s'
    notlatest_msg = 'Not latest for %s'

    # Verify Files.
    for path in filepathgen:
        filehash = get_file_hash(path)
        is_valid = verify_file(filehash)
        if is_valid:
            if check_latest:
                rec = get_record_by_hash(filehash)
                if rec[FILEHASH] in latest:
                    print('%s\t%s\t%s' % (path, valid_msg, latest_msg % rec[SAMPLE]))
                else:
                    print('%s\t%s\t%s' % (path, valid_msg, notlatest_msg % rec[SAMPLE]))
            else:
                print('%s\t%s' % (path, valid_msg))
        else:
            print('%s\t%s' % (path, invalid_msg))

if __name__ == '__main__':
    main()
