#!/usr/bin/env python

import argparse
import asyncio
import dbl.api
import logging

def setup_logging(wants_verbose):
    if wants_verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(format='%(message)s', level=level)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

async def login(creds):
    client = dbl.api.Client(creds)
    await client.login()
    await client.post_login()
    if client.has_presents():
        await client.get_all_presents()
    else:
        logging.info('No presents received')
    await client.close()

def main():
    parser = argparse.ArgumentParser(description='Dragon Ball Legends API client')
    parser.add_argument('-c', '--credentials', metavar='<file.json>', required=True, type=str, help='JSON file containing credentials')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information.')
    args = parser.parse_args()

    setup_logging(args.verbose)

    asyncio.run(login(args.credentials))

if __name__ == '__main__':
    main()
