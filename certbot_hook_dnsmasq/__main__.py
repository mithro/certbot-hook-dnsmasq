"""Allow running as: python -m certbot_hook_dnsmasq"""

import sys

from certbot_hook_dnsmasq.cli import main

sys.exit(main())
