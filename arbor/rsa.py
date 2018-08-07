'''RSA Key Operations'''

import os

import Crypto.Signature.PKCS1_v1_5 as PKCS
from Crypto.PublicKey import RSA

from . import (
    DEFAULT_PRIVATE_KEY_FILE,
    DEFAULT_PUBLIC_KEY_FILE,
)


# Bit-length used when generating a new RSA private key.
KEY_SIZE = 3072


def init_rsa(privatekey_path=DEFAULT_PRIVATE_KEY_FILE,
             publickey_path=DEFAULT_PUBLIC_KEY_FILE):
    '''Import RSA keys (or create new if not found) and initialize file
    signer.'''
    if os.path.isfile(privatekey_path):
        privatekey = import_key(privatekey_path)
    else:
        print('RSA keys not found.')
        privatekey = generate_rsa_keys(privatekey_path, publickey_path)
    signer = load_signer(privatekey)
    return signer


def load_signer(privatekey):
    '''Return an RSA PrivateKey object. If key is too small for signing or
    otherwise invalid, an exception is thrown.'''
    signer = PKCS.new(privatekey)
    assert signer.can_sign(), ('Invalid private key - Generate new keys '
                               'before retrying.')
    return signer


def load_verifier(publickey_path):
    if os.path.isfile(publickey_path):
        publickey = import_key(publickey_path)
        verifier = PKCS.new(publickey)
    else:
        raise Exception('Public key file "%s" does not exist' % publickey_path)
    return verifier


def generate_rsa_keys(privatefile=DEFAULT_PRIVATE_KEY_FILE,
                      pubfile=DEFAULT_PUBLIC_KEY_FILE,
                      key_size=KEY_SIZE):
    '''Generate a fresh RSA private/public key pair and write to file.
    Returns the privatekey object.'''
    print('Generating new RSA keys...')
    privatekey = RSA.generate(key_size)
    publickey = privatekey.publickey()
    with open(privatefile, 'wb') as f:
        f.write(privatekey.exportKey())
    with open(pubfile, 'wb') as f:
        f.write(publickey.exportKey())
    print('New RSA keys generated, written to %s, %s' % (privatefile, pubfile))
    return privatekey


def import_key(filepath=DEFAULT_PRIVATE_KEY_FILE):
    '''Import and return the RSA key from the provided file.'''
    with open(filepath, 'rb') as f:
        key = RSA.importKey(f.read())
    return key
