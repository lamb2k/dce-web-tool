"""Refuse unless each .deb named in dependencies.json is present with its pinned sha256, and nothing else is."""
import hashlib
import json
from pathlib import Path
import sys


def check(pins, folder):
    wanted = {row['file']: row['sha256'] for row in json.loads(Path(pins).read_text())['privateUbuntuNoblePackages']}
    found = {path.name: path for path in Path(folder).glob('*.deb')}
    problems = [f'missing {name}' for name in wanted if name not in found]
    problems += [f'not pinned {name}' for name in found if name not in wanted]
    problems += [f'sha256 differs {name}' for name, path in found.items()
                 if name in wanted and hashlib.sha256(path.read_bytes()).hexdigest() != wanted[name]]
    return problems


if __name__ == '__main__':
    problems = check(sys.argv[1], sys.argv[2])
    for problem in problems:
        print(problem, file=sys.stderr)
    sys.exit(1 if problems else 0)
