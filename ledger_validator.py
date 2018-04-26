#!/usr/bin/python2.7

"""
Directory Ledger Validator
Version: 1.0.2
"""

import os
import argparse
import json
from base64 import b64encode, b64decode
import Crypto.Hash.SHA512 as HASH # pip install pycrypto
import Crypto.Signature.PKCS1_v1_5 as PKCS
from Crypto.PublicKey import RSA

# Default Filepath of Ledger.
DEFAULT_LEDGER_FILE = 'eValidate_ledger.json'

# Default Filepath of RSA Public Key.
DEFAULT_PUBLIC_KEY_FILE = 'eValidate-public.key'

# Field names used in ledger.
PATIENT = 'patientid'
SAMPLE = 'localid'
RPTID = 'rptid'
DATE = 'date'
FILEPATH = 'filepath'
FILEHASH = 'hash'
SIGNEDHASH = 'signature'

# Block size for buffering file reads.
BLOCKSIZE = 65536 #64*1024

# Globals initialized by functions.
RECORDS = None
RECORDS_BY_HASH = {}
VERIFIER = None

##########################
# Ledger File Read/Write #
##########################

def read_ledger(filepath=DEFAULT_LEDGER_FILE):
    ''' Read records from ledger file and store in global variable RECORDS. '''
    global RECORDS, RECORDS_BY_HASH
    with open(filepath, 'rb') as f:
        RECORDS = [entry for entry in json.load(f)]
    for rec in RECORDS:
        RECORDS_BY_HASH[rec[FILEHASH]] = rec

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
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            filehash.update(buf)
            buf = afile.read(BLOCKSIZE)
    return filehash

def verify_file(filehash):
    ''' Verify contents of file have not been tampered with. 
        Returns True if file can be matched by digital signature against a ledger record. '''
    rec = get_record_by_hash(filehash)
    if rec:
        sig = b64decode(rec[SIGNEDHASH])
        return VERIFIER.verify(filehash, sig)
    else:
        return False

######################
# Latest File Checks #
######################

def get_latest_info_by_smp(group_by_filetype=False):
    ''' Determine which rptid and set of hashes are from the latest report version for each sample. '''
    defaultdic = {
                  DATE : 0,
                  RPTID : set(),
                  FILEHASH : [],
                  SIGNEDHASH : [],
                 }
    latest_by_smp = {}
    for rec in RECORDS:
        smp = rec[SAMPLE]
        if group_by_filetype:
            # Refine grouping to distinguish file extension.
            smp += os.path.splitext(rec[FILEPATH])[1]
        date = int(rec[DATE]) # dev_note: millisecond timestamp may be a string in json file.
        maxdic = latest_by_smp.setdefault(smp, defaultdic.copy())
        if date == maxdic[DATE]:
            # Same date found - supplementary file, add file hash.
            maxdic[FILEHASH].append(rec[FILEHASH])
            maxdic[SIGNEDHASH].append(rec[SIGNEDHASH])
            maxdic[RPTID].add(rec[RPTID]) # JJ_TODO: Is it possible for multiple rptids of one sample to share a the same date?
        elif date > maxdic[DATE]:
            # Newer date found, replace old one, create new list for valid hashes.
            maxdic[DATE] = date
            maxdic[FILEHASH] = [rec[FILEHASH]]
            maxdic[SIGNEDHASH] = [rec[SIGNEDHASH]]
            maxdic[RPTID] = set([rec[RPTID]])
        else:
            # Older date, ignore.
            pass
    return latest_by_smp

def get_latest_hashes(group_by_filetype=False):
    ''' Get set of hash digests from the ledger associated with the latest reports of each sample. '''
    # Flatten signatures of latest rptid into a single list.
    latest_by_smp = get_latest_info_by_smp(group_by_filetype)
    listoflists = [s[FILEHASH] for s in latest_by_smp.itervalues()]
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
    parser.add_argument('paths', nargs='+', help='One or more paths of report files to verify')
    args = parser.parse_args()
    run(args.paths,
        args.check_latest,
        args.ledger,
        args.publickey)

def run(filepaths, check_latest=False, ledger_path=DEFAULT_LEDGER_FILE, publickey_path=DEFAULT_PUBLIC_KEY_FILE):
    # Initial setup.
    read_ledger(ledger_path)
    load_verifier(publickey_path)
    latest = get_latest_hashes(group_by_filetype=True) #Note: 'True' may return multiple hashes per sample.
    
    valid_msg = 'Valid'
    invalid_msg = 'Not valid'
    latest_msg = 'Latest for %s'
    notlatest_msg = 'Not latest for %s'
    
    # Verify Files.
    for path in filepaths:
        filehash = get_file_hash(path)
        is_valid = verify_file(filehash)
        if is_valid:
            if check_latest:
                rec = get_record_by_hash(filehash)
                if rec[FILEHASH] in latest:
                    print '%s\t%s\t%s' % (path, valid_msg, latest_msg % rec[SAMPLE])
                else:
                    print '%s\t%s\t%s' % (path, valid_msg, notlatest_msg % rec[SAMPLE])
            else:
                print '%s\t%s' % (path, valid_msg)
        else:
            print '%s\t%s' % (path, invalid_msg)

if __name__ == '__main__':
#    pass
    main()
