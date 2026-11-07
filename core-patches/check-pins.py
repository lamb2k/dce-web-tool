#!/usr/bin/env python3
"""Check every file hash in pins.json that names a file in this folder. Exit 1 on any difference.

rec-wasm files and build receipts describe a separate build tree: they are not checked here.
"""
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent


def check(folder=HERE):
    pins = json.loads((folder/'pins.json').read_text())
    problems = []
    for section in ('patchSha256', 'adapterSha256'):
        for name, expected in pins[section].items():
            path = folder/name
            if not path.is_file():
                problems.append(f'missing {name}')
            elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                problems.append(f'differs {name}')
    return problems


if __name__ == '__main__':
    found = check()
    for problem in found:
        print(problem, file=sys.stderr)
    print('pins: FAIL' if found else 'pins: PASS')
    sys.exit(1 if found else 0)
