"""Constants for testing."""

from __future__ import unicode_literals


LEDGER_RECORDS = [
    {
        'previousblockhash': b'',
        'localid': 'smpid_0',
        'filehash': b'wg14UvdBnxg90dxMhdaquhxqUcmckemoEbtxGMWo4e6BXjFIU7h'
                    b'iiNAXDjhnmIvIYq7A08xixCS7qIEuJyDfSw==',
        'blockindex': 0,
        'blocksignature': b'UQks4EgJJbFTp4piYJYtNXdGXLTodo8CzUdqCPqALY9qf'
                          b'vcLaoo0tIyiiQ/ozhz5FPGbolCwmAV4OTqaz7DAB7trT1'
                          b'VVod12WMcx01x0MThfagqqqS789O4iCkbRUFvPHtLy2ki'
                          b'/plLS0XT6oDBrZYxDZL+gpWbq9Q3VzgmxZCE=',
        'blocktimestamp': 1533071723.108952,
        'patientid': '22651339',
        'rptid': 'rptid_100002',
        'rpttype': 'xml',
        'rptdate': 1010316094784
    },
    {
        'previousblockhash': b'sRWuZHeIZffe2Bl/sJ//uPsLjBKLKGiNTnIbELU3RoE/'
                             b'pHRCJrd5rFIL2wRgQS9sThtKfx6BSZnHT1cp9z1QpQ==', 
        'localid': 'smpid_0', 
        'filehash': b'Hwh+kaKZ/sqhcL4KBo0gXoiWUw9P1TsuQfUBEu8bdADFBWBJCJWw2'
                    b'Rcdu3LOxCOCbM6N3p/xFhvzzpBbV2d+uA==', 
        'blockindex': 1, 
        'blocksignature': b'uYDHf8oIXYcwvQnn7V67j61PO/WWPK2F+mvuwEaRK79lRN3'
                          b'VXH4Dr1VMSe9k8vCexnO0ACuBLA9h8wDeXqzVyy7Gz0bjvu'
                          b'BM5NGMRPoR2Z/EQaQyLlEA18zg1jB6Tt/osIcrlT5ozKpks'
                          b's7pupZw45Ti3Tjy9eZ5lFFTMh59uhE=', 
        'blocktimestamp': 1533071723.112062, 
        'patientid': '123456', 
        'rptdate': 1023512400000, 
        'rptid': 'rptid_100000', 
        'rpttype': 'pdf'
    },
]

BLOCK_0, BLOCK_1 = LEDGER_RECORDS
