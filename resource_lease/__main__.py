"""Allow ``python -m resource_lease ...``."""

import sys

from .cli import main

sys.exit(main())
