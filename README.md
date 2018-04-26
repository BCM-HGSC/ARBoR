# eValidator

Simple offline verification of file integrity against modification or corruption

## Requirements:
- Python 2.7
  - PyCrypto package: `pip install pycrypto` 
- Ledger File *(eValidate_ledger.json)*
- Public Key *(eValidate-public.key)*

## Usage:
#### Verifying that a file's contents have not been altered
`python ledger_validator.py --ledger=eValidate_ledger.json --publickey=eValidate-public.key report.pdf`

#### Checking if file is the most recent report version for its sample
Include the optional flag `--check-latest`
