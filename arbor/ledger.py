"""Serialization code. Where `blockchain` is logical, `ledger is physical.`
Gets into details about reading metadata out of HTML files."""

from __future__ import unicode_literals
import fnmatch
import glob
import itertools
import json
import os
import re
import time
import xml.etree.ElementTree as ET
# https://docs.python.org/2/library/xml.etree.elementtree.html

from bs4 import BeautifulSoup
from bs4 import Comment

from . import DEFAULT_LEDGER_FILE
from .blockchain import (
    append_block,
    dump,
    get_blockchain,
    hash_files,
    is_already_in_ledger,
    PATIENT,
    SAMPLE,
    RPTID,
    RPTDATE,
    FILEPATH,
    FILEHASH,
    REPORTTYPE,
    BLOCKINDEX,
    BLOCKTIMESTAMP,
    PREVBLOCKHASH,
    BLOCKHASH,
    BLOCKSIG,
)


# Date format used in the HTML reports.
DATE_FORMAT = '%m/%d/%Y'

# Bash-style pattern of report files for which to scan.
XML_FILENAME_PATTERN = '*.xml'

# Bash-style pattern of report files for which to scan.
HTML_FILENAME_PATTERN = '*.html'

# Pattern of supplemental files for which to search.
SUPPL_FILENAME_PATTERN = '*.pdf'

# XPath XML tag descriptors of relevant data in xml files.
XML_RPTID_TAG = './objMessage/report/reportIdentifier'
XML_SAMPLE_TAG = './objMessage/report/order/localOrderNumber'
XML_RPTDATE_TAG = './origin/org.pcpgm.gis.fedmsg.v4.EnvelopeSender/timestampMs'
XML_PATIENT_TAG = './objMessage/report/order/senderOrderNumber'

# Field names to retrive from HTML report PHI table.
HTML_RPTID_KEY = 'JJ_TODO:HTML_RPTID_KEY'
HTML_SAMPLE_KEY = 'Accession #'
HTML_RPTDATE_KEY = 'Report Date'
HTML_PATIENT_KEY = 'Patient ID'


# Mapping of xml report tags to ledger field names.
# Keys represent required fields to parse from the report XML files.
XML_TAGS_MAP = {
                XML_SAMPLE_TAG: SAMPLE,
                XML_RPTID_TAG: RPTID,
                XML_RPTDATE_TAG: RPTDATE,
                XML_PATIENT_TAG: PATIENT,
}

# Mapping of html report fields to ledger field names.
HTML_FIELDS_MAP = {
                   HTML_SAMPLE_KEY: SAMPLE,
                   HTML_RPTID_KEY: RPTID,
                   HTML_RPTDATE_KEY: RPTDATE,
                   HTML_PATIENT_KEY: PATIENT,
}

# JJ_TODO: Question: Should RPTID not be required for the XML files as well?
# HTML report will be considered invalid if any values of these fields are
# None.
HTML_REQUIRED_FIELDS = set([
                            SAMPLE,
                            # Note: allow None for HTML_RPTID_KEY field to
                            # support legacy HTML reports.
                            RPTDATE,
                            PATIENT,
])
assert HTML_REQUIRED_FIELDS.issubset(list(HTML_FIELDS_MAP.values())), (
    'required fields must be included as keys in HTML_FIELDS_MAP'
)


def read_ledger(filepath=DEFAULT_LEDGER_FILE, optional=False):
    '''Read records from ledger file and store in global blockchain.'''
    if optional and not os.path.exists(filepath):
        return  # It's OK if the ledger is missing and optional is True.
    blockchain = get_blockchain()
    with open(filepath, 'rb') as f:
        blockchain.blocks = [entry for entry in json.load(f)]
    for rec in blockchain.blocks:
        convert_field_to_binary(rec, FILEHASH)
        convert_field_to_binary(rec, BLOCKSIG)
        convert_field_to_binary(rec, PREVBLOCKHASH)
        blockchain.by_hash[rec[FILEHASH]] = rec


def convert_field_to_binary(record, field_name):
    old = record[field_name]
    new = old.encode('ascii')
    record[field_name] = new


#####################
# Ledger Generation #
#####################

def create_ledger(signer, paths=[''],
                  recursive=True, ledger_path=DEFAULT_LEDGER_FILE):
    # Assert paths are directories.
    paths = [cleanup_dirpath(path) for path in paths]
    # Create XML records.
    xml_records = create_xml_records(paths, recursive)
    # Create PDF records based on HTML reports.
    pdf_records = create_pdf_records(paths, recursive)
    # Add digital signature of file to each record in ledger.
    all_records = xml_records + pdf_records
    hash_files(all_records)
    # Remove filepath from records - not needed in ledger.
    for rec in all_records:
        rec.pop(FILEPATH, None)
    # Sort records before writing.
    all_records.sort(key=get_comparator())
    # Add records to the existing chain.
    blockchain = get_blockchain()
    for rec in all_records:
        append_block(blockchain.blocks, signer, rec)
    # Write records to ledger file.
    # JJ_TODO: Append to file instead of overwriting existing.
    write_ledger(blockchain.blocks, ledger_path)


def write_ledger(ledger_list, filepath=DEFAULT_LEDGER_FILE):
    '''Write ledger records to file.'''
    with open(filepath, 'w') as f:
        dump(ledger_list, f, indent=2, sort_keys=True)
        # JJ_TODO: yaml.dump(ledger_list, f, default_flow_style=False)


def get_comparator():
    '''Lambda function that can be used for sorting report records.'''
    return lambda record: (record[RPTDATE], record[REPORTTYPE])


def create_xml_records(paths, recursive):
    '''Find xml files in paths and process them into records for ledger.'''
    # Search paths for XML report files.
    xml_path_iters = [get_filepaths(path, XML_FILENAME_PATTERN, recursive)
                      for path in paths]
    xml_filepaths = itertools.chain.from_iterable(xml_path_iters)
    # Parse XML files.
    xml_records = parse_xml_files(xml_filepaths)
    # Add 'type' to xml records.
    for rec in xml_records:
        rec[REPORTTYPE] = 'xml'
        # JJ_TODO: Use a defined constant instead of string literal.
    return xml_records


def parse_xml_files(filepaths):
    '''Parse data needed for ledger from XML files. Returns a dictionary
    containing initial ledger entries for valid XML files.'''
    records = list()
    for path in filepaths:
        # Skip file if already in ledger
        if is_already_in_ledger(path):
            continue
        try:
            # Read XML file.
            xmlroot = ET.parse(path).getroot()
        except ET.ParseError as e:
            # TODO_LATER: Set up a logger for messages like this.
            print('INFO: Skipped unparsable XML file: %s' % path)
            continue
        if not xmlroot.findtext(XML_RPTID_TAG):
            print('INFO: Skipped invalid report file: %s' % path)
            continue
        # Collect required fields into dict.
        rec = {XML_TAGS_MAP[tag]: xmlroot.findtext(tag)
               for tag in XML_TAGS_MAP}
        # Cheap bugfix - make sure timestamp is an integer instead of string.
        rec[RPTDATE] = int(rec[RPTDATE])
        # Check required fields are valid.
        if None or '' in list(rec.values()):
            raise Exception('Report file is missing required fields! %s, %s'
                            % (path, rec))
        rec[FILEPATH] = path
        # Add dict to list.
        records.append(rec)
    return records


def create_pdf_records(paths, recursive):
    '''Find html and pdf files in paths and create ledger records for pdf
    reports based on parsed html data.'''
    # Search paths for HTML report files.
    html_path_iters = [get_filepaths(path, HTML_FILENAME_PATTERN, recursive)
                       for path in paths]
    html_filepaths = itertools.chain.from_iterable(html_path_iters)
    # Create PDF records based on HTML reports.
    pdf_records = create_pdf_rec_from_html_reports(html_filepaths)
    # Add 'type' to pdf records.
    for rec in pdf_records:
        rec[REPORTTYPE] = 'pdf'
        # JJ_TODO: Use a defined constant instead of string literal.
    return pdf_records


def create_pdf_rec_from_html_reports(html_report_filepaths):
    '''Create ledger records for pdf reports based on
    data parsed from its html report file equivalent.'''
    records = list()
    for html_path in html_report_filepaths:
        try:
            pdf_path = get_pdf_path(html_path)
            if not pdf_path:
                    raise Exception('No pdf file exists for this html report')
            # Skip file if already in ledger
            if is_already_in_ledger(pdf_path):
                continue
            rec = parse_html_report(html_path)
            # Reformat date to time in milliseconds.
            rec[RPTDATE] = get_timestamp(rec[RPTDATE])
            # Check required fields are valid.
            # JJ_TODO: Consider having the Required_Fields validation in
            # create_ledger() function to operate on all records at same time.
            if None or '' in [rec[field] for field in HTML_REQUIRED_FIELDS]:
                raise Exception('Report file is missing required '
                                'fields! %s, %s' % (html_path, rec))
            rec[FILEPATH] = pdf_path
            records.append(rec)
        except Exception as e:
            print('WARN: Skipped HTML file: "%s" - %s' % (html_path, e))
    return records


def cleanup_dirpath(path):
    '''Ensure path is a directory, and append a separator ('/' for UNIX) if
    needed.'''
    cleanpath = os.path.normpath(path)
    if not os.path.isdir(cleanpath):
        raise Exception('Path should be a directory, inputted path was not a '
                        'directory: "%s"' % path)
    cleanpath = os.path.join(cleanpath, '')
    return cleanpath


#########################
# HTML Report Functions #
#########################

def parse_html_report(html_report_filepath):
    '''Get ledger entry fields from an html report.'''
    htmlsoup = make_soup(html_report_filepath)
    phi_table = get_phi_table(htmlsoup)
    fields = get_fields_from_phi_table(phi_table)
    fields[HTML_RPTID_KEY] = get_rptid_from_html(htmlsoup)
    return {HTML_FIELDS_MAP[field]: fields.get(field)
            for field in HTML_FIELDS_MAP}


def make_soup(html_report_filepath):
    '''Helper method, Read in HTML file using BeautifulSoup library.'''
    with open(html_report_filepath, 'rb') as f:
        soup = BeautifulSoup(f, 'html.parser')
    return soup


def get_phi_table(htmlsoup):
    '''Find PHI table element in HTML file using text that is known to exist
    within table element.'''
    # Use regular expression to identify cell nested within phi table.
    known_text_regexp = '.*%s.*' % HTML_RPTDATE_KEY
    pattern = re.compile(known_text_regexp)
    # JJ_TODO: Using regexp up front is probably a performance bottleneck.
    # Consider finding all table elements and then determining which is the
    # correct one.
    matches = htmlsoup.find_all(text=pattern)
    tables = [match.findParent('table')
              for match in matches
              if match.findParent('table')]  # If-clause is needed to exclude
    # 'None' list elements.
    if len(tables) == 1:
        phi_table = tables[0]
    else:
        raise Exception('Unable to unequivocally determine PHI table in '
                        'HTML file')
    return phi_table


def get_fields_from_phi_table(phi_table):
    '''Convert the PHI Table HTML element into a dictionary.
    Note, whitespace and trailing colons are stripped.'''
    fields = {}
    table_rows = phi_table.findAll('tr')
    for row in table_rows:
        cells = row.findAll('td')
        cell_iter = iter(cells)
        try:
            while True:
                # Read field name and value from two contiguous cells.
                c1 = next(cell_iter)
                c2 = next(cell_iter)
                # Strip trailing colon.
                key = c1.getText(strip=True).rsplit(':', 1)[0]
                val = c2.getText(strip=True)
                fields[key] = val
        except StopIteration:
            pass
    return fields


# TODO: Get PHI table elements in similar way as get_rptid_from_html()
def get_rptid_from_html(htmlsoup):
    '''Get the Report ID from the HTML report object.'''
    # <!-- ##reportID:rptid_100000 -->
    comments = htmlsoup.find_all(string=lambda text: isinstance(text, Comment))
    rptid = None
    RPTID_HTML_PREFIX = '##reportID:'
    for comment in comments:
        comment = comment.strip()
        if comment.startswith(RPTID_HTML_PREFIX):
            rptid = comment[len(RPTID_HTML_PREFIX):]
            break
    return rptid


def get_pdf_path(html_report_filepath):
    '''Return path to a real pdf file with the same name and in the same
    directory as html_report_filepath. Otherwise, returns None.
    For example, "dir/my_report.html" might return "dir/my_report.pdf".'''
    paths = find_similar_files(html_report_filepath, suffix_pattern='.pdf')
    return paths[0] if paths else None


########
# Util #
########

def get_timestamp(date_str, format_str=DATE_FORMAT):
    '''Convert formatted date string to millisecond timestamp.'''
    return int(time.mktime(time.strptime(date_str, format_str))) * 1000


def find_similar_files(filepath, excludefiles=set(),
                       suffix_pattern=SUPPL_FILENAME_PATTERN):
    '''Find files in the same directory with the same base name as filepath.
    Paths in excludefiles are excluded from the return.
    e.g. 'rpdir/rpt1.xml' may return
    [rpdir/rpt1.pdf, rpdir/rpt1-otherfile.txt]'''
    # JJ_TODO: Consider: merge functionality into get_filepaths().
    # Strip off file extension, and add wildcard.
    base = os.path.splitext(filepath)[0]
    pattern = base + suffix_pattern
    filepaths = [path for path in glob.glob(pattern)
                 if path not in excludefiles and os.path.isfile(path)]
    return filepaths


def get_filepaths(directory, filepattern, recursive=False):
    '''Generator function for filepaths of files with names that match
    filepattern within directory. Additionally, if recursive is True, then
    subdirectories within directory will also be searched.'''
    if recursive:
        for root, dirs, files in os.walk(directory):
            for f in files:
                if fnmatch.fnmatch(f, filepattern):
                    filepath = os.path.join(root, f)
                    yield filepath
    else:
        pattern = directory + filepattern
        for filepath in glob.glob(pattern):
            if os.path.isfile(filepath):
                yield filepath
