# ARBOR (Authenticated Resources in Blockchain Registry)

Simple offline verification of file integrity against modification or corruption

## Requirements:
- Python 2.7
  - PyCrypto package: `pip install pycrypto` 
- Ledger File *(eValidate_ledger.json)*
- Public Key *(eValidate-public.key)*

## Usage:

#### Generating the ledger
`python ledger_generator.py --ledger=arbor_ledger.json --privatekey=arbor-private.key --publickey=arbor-public.key --recursive reportdir/`

#### Verifying that a file's contents have not been altered
`python ledger_validator.py --ledger=arbor_ledger.json --publickey=arbor-public.key report.pdf`

#### Checking if file is the most recent report version for its sample
Include the optional flag `--check-latest`
