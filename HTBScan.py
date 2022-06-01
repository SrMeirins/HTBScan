#!/usr/bin/python3

import signal, os, time, argparse, subprocess, shlex
from pwn import *


#Ctrl + C :
def ctrl_c(sig, frame):
    print("\n\n[*] Saliendo ... [*]\n")
    sys.exit(1)

signal.signal(signal.SIGINT, ctrl_c)

#Argumentos:

parser = argparse.ArgumentParser(usage='%(prog)s -i <ip address> -m <scanning mode>', description='Automatic program to scan HTB machines.')
parser.add_argument('-i', '--ip', type=str, help='IP Adress', required=True)
parser.add_argument('-m', dest='mode', choices=['t5', 'sS', 'udp'], help='Scanning Mode: t5 : Linux  ;     sS : Windows       udp : UDP Scan', required=True)

args = parser.parse_args()

#Variables Globales

ip = args.ip
mode = args.mode

#Funciones


def notroot():
    if os.getuid() !=0:
        log.failure("This program must be run as sudo.\n")
        sys.exit(1)

def inputIP():
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if re.search(regex, ip):
        return True
    else:
        log.failure("Incorrect IP Address Format\n")
        sys.exit(1)

def nmap():
    
    command = subprocess.run(['which', 'nmap'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if command.returncode != 0:
        log.failure("I can't found Nmap in your system. Try apt install nmap")
        sys.exit(1)
    else:
        return True

def t5mode(): 
    print("\n")
    p0 = log.success("Command --> (nmap -p- --open -sVC -T5 -n %s -oN Scanner)" % ip)
    time.sleep(1)  
    p1 = log.progress("Looking for open ports (This may take a while)")
    command = 'nmap -p- --open -sVC -T5 -n %s -oN Scanner.txt' % ip
    args = shlex.split(command)
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p2 = log.success("File Scanner.txt created!!")
    

def ssmode():
    print("\n")
    p0 = log.success("Command --> (nmap -p- --open -sSVC --min-rate 5000 -n -Pn %s -oN Scanner)" % ip)
    time.sleep(1)
    p1 = log.progress("Looking for open ports (This may take a while)")
    command = 'nmap -p- --open -sSVC --min-rate 5000 -n -Pn %s -oN Scanner.txt' % ip
    args = shlex.split(command)
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
    p2 = log.success("File Scanner.txt created!!")

def udpmode():
    print("\n")
    p0 = log.success("Command --> (nmap --top-ports 100 --open -sU -sVC -T5 -n %s -oN Scanner)" % ip)
    time.sleep(1)
    p1 = log.progress("Looking for UDP open ports (This may take a while)")
    command = 'nmap --top-ports 100 --open -sU -sVC -T5 -n %s -oN ScannerUdp.txt' % ip
    args = shlex.split(command)
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p2 = log.success("File ScannerUdp.txt created!!")
    

#Main
if __name__ == '__main__':
    notroot()
    inputIP()
    nmap()
    if mode == 't5':
        t5mode()
    elif mode == 'sS':
        ssmode()
    else:
        udpmode()
    
