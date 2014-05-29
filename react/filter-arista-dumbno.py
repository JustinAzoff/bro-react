#!/usr/bin/env python
import sys
import socket
import json
import time

class ACLClient:
    def __init__(self, host, port=9000):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1)

    def add_acl(self, src, dst, proto="ip", sport=None, dport=None):
        msg = json.dumps(dict(src=src,dst=dst,proto=proto,sport=sport,dport=dport))
        self.sock.sendto(msg, self.addr)
        try :
            data, addr = self.sock.recvfrom(1024)
            return True
        except socket.timeout:
            return None

def main():
    lines = sys.stdin.read().strip().split("\n")
    manager, src, dst, sport, dport = lines

    sport, proto = sport.split("/")
    dport, _     = dport.split("/")

    c=ACLClient(manager)
    for x in range(1,31):
        if c.add_acl(src, dst, proto, sport, dport):
            print "ok, attempt:", x
            return 0
    print "fail"
    return 1

if __name__ == "__main__":
    sys.exit(main())
