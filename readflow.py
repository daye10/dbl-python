#!/usr/bin/env python

import argparse

from dbl import scream, api

from datetime import datetime
from mitmproxy import tcp, io
from mitmproxy.utils import strutils
from mitmproxy.exceptions import FlowReadException

def load_flow(path):
    with open(path, "rb") as flowfile:
        freader = io.FlowReader(flowfile)
        try:
            for f in freader.stream():
                if isinstance(f, tcp.TCPFlow):
                    for msg in f.messages:
                        packet = msg.content
                        timestamp = datetime.fromtimestamp(msg.timestamp)
                        while True:
                            payload, packetLen = scream.Packet.decode(packet)
                            if msg.from_client:
                                cmd = scream.Request.parse(payload)
                            else:
                                cmd = scream.Response.parse(payload)
                            print(f'{timestamp} {cmd}')
                            if len(packet) - packetLen > 0:
                                packet = msg.content[packetLen:]
                            else:
                                break

        except FlowReadException as e:
            print(f"Flow file corrupted: {e}")

def main():
    parser = argparse.ArgumentParser(description='Decode packets from mitmproxy flow file')
    parser.add_argument('flow', metavar='flow-file', help='Flow file from mitmproxy')
    args = parser.parse_args()
    load_flow(args.flow)

main()
