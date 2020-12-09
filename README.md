# Nmap-short-scan
Perform a standard top-1000-port TCP/UDP scan with nmap and save the output to various formats.
## Description
This tool is a python wrapper for specific nmap commands. It outputs nmap results to gnmap, nmap, xml, and html formats.

This application is intended for Linux systems using Python 3.X.

## Download
Open a terminal shell and use `git clone` to download.
```bash
git clone https://github.com/syyntax/nmap-short-scan.git
```

## Requirements
The following are requirements to use this script successfully:
* Python 3.X
* xsltproc

## Options
| Option                        | Description                                                                            |
|-------------------------------|----------------------------------------------------------------------------------------|
| --analyst [NAME]              | The name of the analyst running the tool (e.g. "John Smith; default is OS username)    |
| --client [NAME]               | The business name of the client (e.g. "Bob's Repair Shop")                             |
| --contract [NUMBER]           | The 8-digit contract number (e.g. 12345678)                                            |
| --scope [FILE]                | The relative filename of the scope file (e.g. Documents/scope.txt)                     |

## Usage
### Create a scope file
First, create a scope file. This should be a plain text file with IPs/URLs separated by newlines.
```text
192.168.1.5
192.168.1.6
my.site.org
```
### Enter the command
Enter the command. Use the example below as a reference.
```bash
sudo python3 nmap-short-scan.py --analyst jsmith --client "Bob's Repair Shop" --contract 12345678 --scope scope.txt
```

