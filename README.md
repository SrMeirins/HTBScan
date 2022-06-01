# HTBScan

Nmap auto-scanning for HTB Machines.

Usage :  python3 HTBScan.py -i <IP> -m <Mode>

Modes:

  - T5: **nmap -p- --open -sVC -T5 -n -oN Scanner.txt**  --> (*Recommended for Linux Machines*)
  - sS: **nmap -p- --open -sSVC --min-rate 5000 -n -Pn -oN Scanner.txt** --> (*Recommended for Windows Machines*)
  - udp: **nmap --top-ports 100 --open -sU -sVC -T5 -n -oN ScannerUDP.txt**  --> (*Udp Scan*)


## How to install:

```sh
git clone https://github.com/SrMeirins/HTBScan
cd HTBScan
pip install -r requirements.txt
```


