# ARBOR (Authenticated Resources in Blockchain Registry)

Clinical laboratories return the results of clinical testing to the ordering physician as a signed report. This report is often a pdf, but can also be a physical paper copy or a structured data format. Here, we introduce ARBOR, an application for tracking the lineage of versioned clinical reports even when they are distributed as pdf or paper copies. It relies on a distributable blockchain ledger that holds the report versions and uses strong encryption to prevent tampering.

The ARBOR system implements a distributable blockchain based ledger containing  digitally signed records that both authenticates PHI files and enables the discovery of newer versions of those files. This blockchain augments the secure delivery path between clinical lab and downstream EMR system by providing a durable method to verify the authenticity of files and detect if relevant, newer files are known to exist. <Reference to paper>

The overall ARBOR system consists of four parts:
- ARBOR Push is integrated into the pipeline of a clinical laboratory. Once the pipeline has generated a clinical report and related files, it uses ARBOR Push to transmit a record about this file to the ARBOR Service.
- ARBOR Service stores records in a public blockchain. It only accepts trusted records from the clinical pipeline.
- ARBOR Client is typically run by an institutional end user as part of the ingestion process for new clinical reports and related files. It fetches new blocks from the ARBOR Service and uses its local copy of the blockchain to validate and identify files.
- ARBORScan  is a mobile app for both <a href='https://goo.gl/QZXpqg' target="_blank">iOS</a> and <a href='https://goo.gl/cLdKB8' target="_blank">Android</a> platforms and is typically run by an end user to fetch metadata about existing reports and check the authenticity and versions of these reports. It also maintains a local copy of the blockchain. It's primary input is scanning QR codes from existing reports.

ARBOR is built using Python and is available for public use. Instructions on  building a ledger and validating the contents of a ledger are provided.

## Requirements:
- Python 2.7 or 3.6+
- PyCrypto package: `pip install pycrypto`
- Ledger File *(eg. arbor-ledger.json)*
- Public Key *(eg. arbor-public.key)*

## Usage:

### Generating the ledger

To generate a ledger, pass in a directory of reports and a private key. The generator currently requires XML files that provide the metadata for associated PDF files. This command will generate a ledger for all files in a folder:

    python ledger_generator.py -h  # for help
    python ledger_generator.py --ledger=arbor-ledger.json --privatekey=arbor-private.key --publickey=arbor-public.key --recursive reportdir/

### Verifying that a file is current and unaltered

To verify files against a ledger, pass in either individual files or directories along with a public key that corresponds to the private key used when generating the ledger. Running the following command on a folder of reports or a single report will identify if the report(s) are valid and up to date:

    python ledger_validator.py -h  # for help
    python ledger_validator.py --ledger=arbor-ledger.json --publickey=arbor-public.key --check-latest reportdir
