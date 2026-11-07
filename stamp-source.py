#!/usr/bin/env python3
"""Run before each site deploy: public/source.json names what the page's "Source and licences" link opens.

  python stamp-source.py <version tag or full commit of the public repository>

The GPL source must be reachable, so this refuses a tag or commit that the public repository does not show as a branch or tag tip.
It never records a commit of the repository this folder is developed in. Not tracked by git."""
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PUBLIC = "https://github.com/lamb2k/dce-web-tool"


def published(ref, listing):
    """True when ls-remote's output shows ref as a commit or as a tag."""
    for line in listing.splitlines():
        commit, _, name = line.partition("\t")
        if ref == commit or name in (f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"):
            return True
    return False


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[0-9A-Za-z._-]{1,64}", sys.argv[1]):
        sys.exit(__doc__)
    ref = sys.argv[1]
    run = subprocess.run(["git", "ls-remote", PUBLIC], capture_output=True, text=True, timeout=60)
    if run.returncode or not published(ref, run.stdout):
        sys.exit(f"stamp-source: {PUBLIC} does not show {ref}: publish it first")
    (HERE / "public/source.json").write_text(json.dumps({"ref": ref}) + "\n", encoding="ascii")
    print(f"source.json: {ref}")


if __name__ == "__main__":
    main()
