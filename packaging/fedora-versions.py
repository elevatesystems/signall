#!/usr/bin/env python3
"""Print the Fedora releases Signall is built and tested for, as a JSON list.

That is Fedora 40 (the oldest Signall supports) through the newest stable release, read from
Fedora's release list (Bodhi), so a new Fedora is picked up without editing anything.

    packaging/fedora-versions.py            [40, 41, ..., 45]
    packaging/fedora-versions.py --newest   45
"""
import json
import sys
import time
import urllib.request

OLDEST = 40
BODHI = "https://bodhi.fedoraproject.org/releases/?exclude_archived=1&rows_per_page=100"


def newest_stable() -> int:
    for attempt in range(4):
        try:
            with urllib.request.urlopen(BODHI, timeout=30) as response:
                releases = json.load(response)["releases"]
            break
        except OSError:
            if attempt == 3:
                raise
            time.sleep(10 * (attempt + 1))
    stable = [int(r["version"]) for r in releases
              if r["id_prefix"] == "FEDORA" and r["state"] == "current" and r["version"].isdigit()]
    if not stable:
        raise SystemExit("Bodhi listed no current Fedora releases")
    return max(stable)


if __name__ == "__main__":
    newest = newest_stable()
    print(newest if "--newest" in sys.argv[1:] else json.dumps(list(range(OLDEST, newest + 1))))
