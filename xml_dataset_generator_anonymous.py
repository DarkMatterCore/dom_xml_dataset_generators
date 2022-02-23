#!/usr/bin/env python3

"""
 * xml_dataset_generator_anonymous.py
 *
 * Copyright (c) 2022, DarkMatterCore <pabloacurielz@gmail.com>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

from __future__ import print_function

import os
import sys
import re
import base64
import subprocess
import traceback

from argparse import ArgumentParser
from typing import List, Union, Tuple, Dict, Pattern, TYPE_CHECKING

SCRIPT_NAME: str = os.path.basename(sys.argv[0])

INITIAL_DIR: str = os.path.abspath(os.path.dirname(__file__))

WIIU_TXT_PATH: str = os.path.join('.', 'wiiu_nus_sorted.txt')
OUTPUT_PATH:   str = os.path.join('.', 'out')

PROPERTIES_COUNT: int = 6

XML_HEADER: str = '<?xml version="1.0" encoding="utf-8"?>\n'
XML_HEADER +=     '<!DOCTYPE datafile PUBLIC "http://www.logiqx.com/Dats/datafile.dtd" "-//Logiqx//DTD ROM Management Datafile//EN">\n'
XML_HEADER +=     '<datafile>\n'
XML_HEADER +=     '  <header>\n'
XML_HEADER +=     '  </header>\n'

XML_FOOTER: str = '</datafile>\n'

HTML_LINE_BREAK:   str = '&#xA;'

DEFAULT_DUMP_DATE: str = '2022-02-01'
DEFAULT_DUMPER:    str = '!anonymous'
DEFAULT_COMMENT2:  str = ''

GIT_BRANCH: str = ''
GIT_COMMIT: str = ''
GIT_REV:    str = ''

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def utilsGetPath(path_arg: str, fallback_path: str, is_file: bool, create: bool = False) -> str:
    path = os.path.abspath(os.path.expanduser(os.path.expandvars(path_arg if path_arg else fallback_path)))

    if not is_file and create: os.makedirs(path, exist_ok=True)

    if not os.path.exists(path) or (is_file and os.path.isdir(path)) or (not is_file and os.path.isfile(path)):
        raise Exception("Error: '%s' points to an invalid file/directory." % (path))

    return path

def utilsRunGit(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(['git'] + args, capture_output=True, encoding='utf-8')

def utilsGetGitInfo() -> None:
    global DEFAULT_COMMENT2, GIT_BRANCH, GIT_COMMIT, GIT_REV

    # Get git branch.
    proc = utilsRunGit(['rev-parse', '--abbrev-ref', 'HEAD'])
    if not proc.stdout or proc.returncode != 0: raise Exception('Failed to run git!')
    GIT_BRANCH = proc.stdout.strip()

    # Get git commit.
    proc = utilsRunGit(['rev-parse', '--short', 'HEAD'])
    if not proc.stdout or proc.returncode != 0: raise Exception('Failed to run git!')
    GIT_COMMIT = proc.stdout.strip()

    # Generate git revision string.
    GIT_REV = GIT_BRANCH + '-' + GIT_COMMIT
    proc = utilsRunGit(['status', '--porcelain'])
    if proc.returncode != 0: raise Exception('Failed to run git!')
    proc = proc.stdout.strip()
    if proc: GIT_REV += '-dirty'

    # Update default comment2 string.
    comment2_str = DEFAULT_COMMENT2
    DEFAULT_COMMENT2 = '[%s revision %s used to generate XML files]' % (SCRIPT_NAME, GIT_REV)
    if comment2_str: DEFAULT_COMMENT2 += '%s%s' % (HTML_LINE_BREAK, comment2_str)

def utilsGenerateDictionaryFromCsvFile(csv_path: str) -> Dict:
    csv_dict: Dict = {}

    with open(csv_path, 'r') as csv:
        for idx, line in enumerate(csv):
            # Skip first line.
            if idx == 0: continue

            # Get current line in lowercase form.
            cur_line = line.strip().lower()

            # Get properties.
            properties = cur_line.split(';')
            properties_len = len(properties)
            if properties_len < PROPERTIES_COUNT:
                # Commas are used on some lines for some reason.
                for k, v in enumerate(properties):
                    if properties[k].find(',') < 0: continue

                    items = properties[k].split(',')
                    items_len = len(items)

                    properties.pop(k)
                    for l, w in enumerate(items): properties.insert(k + l, w)

                    properties_len = ((properties_len - 1) + items_len)
                    if properties_len >= PROPERTIES_COUNT: break

            file = properties[0].strip()
            size = int(properties[1].strip())
            crc = properties[2].strip()
            md5 = properties[3].strip()
            sha1 = properties[4].strip()
            sha256 = properties[5].strip()

            # Get Title ID and filename.
            (tid, file) = file.split('/')
            tid = tid.strip()
            file = file.strip()

            # Get dictionary for this Title ID.
            tid_dict = csv_dict.get(tid, {})

            # Get dictionary for this file.
            file_dict = tid_dict.get(file, {})

            # Update file dictionary.
            file_dict.update({'size': size, 'crc': crc, 'md5': md5, 'sha1': sha1, 'sha256': sha256})

            # Update Title ID dictionary.
            tid_dict.update({file: file_dict})

            # Update CSV dictionary.
            csv_dict.update({tid: tid_dict})

    return csv_dict

def utilsGenerateXmlDataset(xml_dict: Dict, outdir: str) -> None:
    xml_path = os.path.join(outdir, 'wiiu.xml')
    with open(xml_path, 'w') as xml_file:
        # Write XML file header.
        xml_file.write(XML_HEADER)

        # Process titles.
        for item1 in xml_dict.items():
            tid = item1[0]
            contents_dict = item1[1]

            # Generate metadata.
            title_str  = '  <game name="">\n'
            title_str += '    <archive name="%s" namealt="" region="Unknown" languages="En" showlang="2" version="" devstatus="" additional="" special1="" special2="" gameid="" clone="" regionalparent="" mergeof="" datternote="" stickynote="" />\n' % (tid)
            title_str += '    <flags bios="0" licensed="1" pirate="0" physical="0" complete="1" nodump="0" public="1" dat="1" />\n'
            title_str += '    <source>\n'
            title_str += '      <details section="Trusted Dump" rominfo="" dumpdate="%s" originalformat="Default" knowndumpdate="1" releasedate="" knownreleasedate="0" dumper="!anonymous" project="" tool="Custom" origin="" comment1="" comment2="%s" link1="" link2="" region="" mediatitle="" />\n' % (DEFAULT_DUMP_DATE, DEFAULT_COMMENT2)
            title_str += '      <serials mediaserial1="" mediaserial2="" pcbserial="" romchipserial1="" romchipserial2="" lockoutserial="" savechipserial="" chipserial="" boxserial="" mediastamp="" boxbarcode="" digitalserial1="%s" digitalserial2="" />\n' % (tid)

            rom_str = ''

            # Process file entries.
            for source_dict in contents_dict.items():
                name = source_dict[0]
                size = source_dict[1]['size']
                crc = source_dict[1]['crc']
                md5 = source_dict[1]['md5']
                sha1 = source_dict[1]['sha1']
                sha256 = source_dict[1]['sha256']

                # Generate metadata.
                rom_str += '      <rom forcename="%s" emptydir="0" extension="" item="" date="" format="Default" version="" utype="" size="%d" crc="%s" md5="%s" sha1="%s" sha256="%s" serial="" bad="0" unique="1" mergename="" />\n' % (name, size, crc, md5, sha1, sha256)

            # Update title string.
            title_str += rom_str
            title_str += '    </source>\n'
            title_str += '  </game>\n'

            # Write metadata.
            xml_file.write(title_str)

        # Write XML footer.
        xml_file.write(XML_FOOTER)

def utilsProcessData(input: str, outdir: str) -> None:
    xml_dict: Dict = {}

    # Generate dictionary for the CSV file.
    xml_dict = utilsGenerateDictionaryFromCsvFile(input)

    # Generate output XML dataset.
    utilsGenerateXmlDataset(xml_dict, outdir)

def main() -> int:
    # Get git commit information.
    utilsGetGitInfo()

    parser = ArgumentParser(description='Generate XML dataset from ' + DEFAULT_DUMPER + '\'s Wii U CDN dump.')
    parser.add_argument('--input', type=str, metavar='FILE', help='Path to ' + DEFAULT_DUMPER + '\'s Wii CDN dump. Defaults to \'' + WIIU_TXT_PATH + '\'.')
    parser.add_argument('--outdir', type=str, metavar='DIR', help='Path to output directory. Defaults to \'' + OUTPUT_PATH + '\'.')

    print(SCRIPT_NAME + '.\nRevision: ' + GIT_REV + '.\nMade by DarkMatterCore.\n')

    # Parse arguments.
    args = parser.parse_args()
    input = utilsGetPath(args.input, os.path.join(INITIAL_DIR, WIIU_TXT_PATH), True)
    outdir = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)

    # Do our thing.
    utilsProcessData(input, outdir)

    return 0

if __name__ == "__main__":
    ret: int = 1

    try:
        ret = main()
    except KeyboardInterrupt:
        eprint('\nScript interrupted.')
    except Exception as e:
        traceback.print_exc(file=sys.stderr)

    try:
        sys.exit(ret)
    except SystemExit:
        os._exit(ret)
