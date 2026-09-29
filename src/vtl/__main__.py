"""Allow `python -m vtl`."""

import sys

from .cli import main

sys.exit(main())
