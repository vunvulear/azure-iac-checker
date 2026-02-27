"""Allow running as: python -m iac_checker"""

import sys
from iac_checker.cli import main

if __name__ == "__main__":
    sys.exit(main())
