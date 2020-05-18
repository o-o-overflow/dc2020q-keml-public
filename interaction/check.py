#!/usr/bin/env python2
from __future__ import print_function

from pwn import *
import sys

def main():

    host = sys.argv[1]
    port = int(sys.argv[2])

    conn = remote(host, port)

    PROMPT = b"/ $ "

    result = conn.recvuntil(PROMPT)
    print("Received before the first prompt:", result, file=sys.stderr)

    conn.sendline("ls -1 /")
    result = conn.recvuntil(PROMPT)
    #print("ls result:", result, file=sys.stderr)
    assert 'etc' in result
    assert 'root' in result

    conn.sendline("uname -a")
    result = conn.recvuntil(PROMPT)
    assert "Linux" in result
    print("uname -a:", result, file=sys.stderr)
    
    conn.sendline("exit")
    conn.shutdown(direction="send")
    result = conn.recvuntil("Power down")
    #print("Post exit:", result, file=sys.stderr)

    sys.exit(0)


if __name__ == '__main__':
    main()
    

