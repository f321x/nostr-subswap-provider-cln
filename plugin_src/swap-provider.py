#!/usr/bin/env python3
"""
Core Lightning submarine swap provider plugin using the Electrum Nostr submarine swap protocol.
To run install requirements (pip install -r requirements.txt), then
cp plugin_src/* in the CLN plugin dir, or set plugin=/path/to/swap-provider.py in the CLN config to run.
"""

import asyncio
import sys
from plugin.cln_swap_provider import CLNSwapProvider


async def main():
    """main function starting the plugin"""
    try:
        swap_provider = CLNSwapProvider()
        await swap_provider.run()
    except Exception as e:
        print(e, file=sys.stderr)  # will show e in the CLN logs


if __name__ == "__main__":
    asyncio.run(main())
