"""``python -m pr_scanner``: see :mod:`pr_scanner.cli`."""

import sys

from .cli import main

raise SystemExit(main(sys.argv[1:]))
