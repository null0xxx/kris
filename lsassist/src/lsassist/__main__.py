"""Entry-point stub for T1.02. The real CLI (cli/) does not exist yet."""

from __future__ import annotations

import sys

from lsassist import __version__


def main() -> int:
    print(f"lsassist {__version__}")
    print("cli not installed yet (T1.02 bootstrap: repository + packaging only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
