"""Fix-and-rescan demo. Usage: uv run python scripts/demo_remediation.py --db artifacts/demo/r.db s0.json s1.json ..."""

import sys

from cspm.store.demo import main

if __name__ == "__main__":
    sys.exit(main())
