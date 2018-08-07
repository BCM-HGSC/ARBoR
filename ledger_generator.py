#!/usr/bin/python2.7

"""
Directory Ledger Generator
Author: Jordan M. Jones
"""

import argparse

from arbor import (
    __version__,
    DEFAULT_LEDGER_FILE,
    DEFAULT_PRIVATE_KEY_FILE,
    DEFAULT_PUBLIC_KEY_FILE,
)
from arbor.ledger import create_ledger, read_ledger
from arbor.rsa import init_rsa


###############
# Main Method #
###############

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version',
                        version='%(prog)s {}'.format(__version__))
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Recursively search subdirectories for files '
                             '(default is to ignore subdirectories)')
    parser.add_argument('-l', '--ledger', metavar='LEDGER_FILE',
                        default=DEFAULT_LEDGER_FILE,
                        help='Filepath to use for the ledger file, preferably'
                             ' with the extension \'.json\' (default: %s)'
                             % DEFAULT_LEDGER_FILE)
    parser.add_argument('-P', '--privatekey', metavar='PRIVATE_KEY_FILE',
                        default=DEFAULT_PRIVATE_KEY_FILE,
                        help='Filepath of RSA private key file. If none '
                             'exists, a key will be generated (default: %s)'
                             % DEFAULT_PRIVATE_KEY_FILE)
    parser.add_argument('-p', '--publickey', metavar='PUBLIC_KEY_FILE',
                        default=DEFAULT_PUBLIC_KEY_FILE,
                        help='Filepath of RSA public key file (default: %s)'
                             % DEFAULT_PUBLIC_KEY_FILE)
    parser.add_argument('paths', nargs='+',
                        help='One or more paths of directories that will be '
                             'processed when generating the ledger')
    args = parser.parse_args()
    run(args.paths,
        args.recursive,
        args.ledger,
        args.privatekey,
        args.publickey)


def run(paths, recursive=True, ledger_path=DEFAULT_LEDGER_FILE,
        privatekey_path=DEFAULT_PRIVATE_KEY_FILE,
        publickey_path=DEFAULT_PUBLIC_KEY_FILE):
    # Load or generate RSA keys and file signer.
    signer = init_rsa(privatekey_path, publickey_path)

    # Read existing blockchain.
    read_ledger(ledger_path, True)

    # Create ledger.
    print('Generating Ledger')
    create_ledger(signer, paths, recursive, ledger_path)
    print('Done')


if __name__ == '__main__':
    main()
