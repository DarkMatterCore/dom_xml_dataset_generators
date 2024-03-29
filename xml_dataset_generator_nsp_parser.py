#!/usr/bin/env python3

from __future__ import annotations

import os, sys, re, traceback, time, argparse

MESSAGE_REGEX = re.compile(r"^\(Thread (\d+)\).+", flags=(re.MULTILINE | re.IGNORECASE))

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def utilsGetPath(path_arg: str, fallback_path: str, is_file: bool, create: bool = False) -> str:
    path = os.path.abspath(os.path.expanduser(os.path.expandvars(path_arg if path_arg else fallback_path)))

    if not is_file and create:
        os.makedirs(path, exist_ok=True)

    if not os.path.exists(path) or (is_file and os.path.isdir(path)) or (not is_file and os.path.isfile(path)):
        raise Exception(f'Error: "{path}" points to an invalid file/directory.')

    return path

def utilsProcessLogfile(logfile: str) -> None:
    msg: dict[int, list[str]] = {}

    with open(logfile, 'r', encoding='utf-8') as fd:
        for _, line in enumerate(fd):
            # Get current line.
            cur_line = line.strip()

            # Parse current line.
            thrd_id = re.search(MESSAGE_REGEX, cur_line)
            if not thrd_id:
                continue

            thrd_id = int(thrd_id.group(1))

            # Get thread message list.
            thrd_msg = msg.get(thrd_id, [])

            # Update thread message list.
            thrd_msg.append(cur_line.split(')', 1)[1].strip())

            # Update message dictionary.
            msg.update({ thrd_id: thrd_msg })

    """import pprint
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(msg)"""

    for k, v in msg.items():
        print(f'Thread {k}:\n')

        for l, w in enumerate(v):
            space = '  '

            if w.startswith('Processing'):
                space *= 1
                if l > 0:
                    print('')
            elif w.startswith('Parsing'):
                space *= 2
            else:
                space *= 3

            print(f'{space}- {w}')

        print('')

    sys.stdout.flush()

def main() -> int:
    # Reconfigure console output.
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

    parser = argparse.ArgumentParser(description='Generate ordered stdout/stderr messages from a xml_dataset_generator_nsp.py logfile.')
    parser.add_argument('--logfile', type=str, metavar='FILE', required=True, help='Path to logfile. Must be provided.')

    # Parse arguments. Make sure to escape ampersand characters in input strings.
    args = parser.parse_args()
    logfile = utilsGetPath(args.logfile, '', True)

    # Do our thing.
    utilsProcessLogfile(logfile)

    return 0

if __name__ == "__main__":
    ret: int = 1

    try:
        ret = main()
    except KeyboardInterrupt:
        time.sleep(0.2)
        eprint('\nScript interrupted.')
    except Exception as e:
        traceback.print_exc(file=sys.stderr)

    try:
        sys.exit(ret)
    except SystemExit:
        os._exit(ret)
