#!/usr/bin/python3
from argparse import ArgumentParser
from re import compile, match
from os import getcwd, system
from getpass import getuser

pwd = getcwd() # Get the present working directory
regex_name = compile(f"^[A-Za-z].*\s[A-Za-z].*$") # Regex for first and last names
regex_contract = compile("^[0-9]{8}$") # Regex for client contract numbers
regex_ip4 = compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4]"
                    "[0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") # Regex for IPv4
regex_domain = compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]") # Domain regex

# Create the argument parser and add argument parameters
parser = ArgumentParser(description='Run a short nmap scan.')
parser.add_argument('--analyst', action='store', help='Enter the name of the ' \
'analyst (e.g. John Smith).', type=str, dest='analyst', default=getuser())
parser.add_argument('--client', action='store', help='Enter the name of the ' \
'client (e.g. Evil Corp).', type=str, dest='client', default=None)
parser.add_argument('--contract', action='store', help='Enter the contract ' \
'number (e.g. 20081101).', type=str, dest='contract', default=None)
parser.add_argument('--scope', action='store', help='Enter the filepath of ' \
'the file that contains the list of IPs/URLs (e.g. /path/to/file)', type=str,
dest='scope', default=None)
args = parser.parse_args()

# Create a class for scans that include information for file naming convention
class Scan:
    def __init__(self, analyst: str, client: str, contract: str, scope=None):
        self.analyst = str(analyst)
        self.client = str(client)
        self.contract = str(contract)
        self.scope = scope

# Create a class for IPs/URLs that will used for the Scan.scope attribute
class Asset:
    def __init__(self):
        self.address = str()

    def add(self, address: str):
        if address is None:
            raise Exception(f"You must provide an IP or URL.")
        elif match(regex_ip4, address) or match(regex_domain, address):
            self.address = str(address)
        else:
            raise Exception(f"\"{address}\" does not match a valid pattern for IPv4 or domain.")

# Perform validation check on provided arguments
def run_checks(client: str, contract: str, scope: str):
    if client is None:
        raise Exception(f"You must provide a client name.")
    elif contract is None:
        raise Exception(f"You must provide a contract number.")
    elif scope is None:
        raise Exception(f"You must provide a scope file.")
    else:
        pass

# Create the asset objects based on the lines in the scope file
def create_scope(scope: str):
    """
    :type scope: str
    example: /root/Documents/scope.txt
    """
    obj_list = list()
    with open(scope, 'r') as f:
        scope_list = [x.strip() for x in f.readlines()]

    for i in scope_list:
        tmp_asset = Asset()
        tmp_asset.add(i)
        obj_list.append(tmp_asset)

    return obj_list


def run_scan(obj: object):
    for i in range(0, len(obj.scope)):
        # Run the Top 1000 nmap scan (SYN) on each IP/domain
        print(f"Nmap scan on {obj.scope[i].address}...\nRunning the Top 1000 nmap scan (SYN) on each IP/domain...")
        system(f"nmap -sS -vv -n -Pn --max-retries 2 --top-ports 1000 -oA {pwd}/{obj.client.replace(' ', '').lower()}-"
               f"{obj.contract}-date-nmap-t1000-{obj.analyst} {obj.scope[i].address}")

        # Run the Top 1000 nmap scan (UDP) on each IP/domain
        print(f"Nmap scan on {obj.scope[i].address}...\nRunning the Top 1000 nmap scan (UDP) on each IP/domain...")
        system(f"nmap -sU -vv -n -Pn --max-retries 2 --top-ports 1000 -oA {pwd}/{obj.client.replace(' ', '').lower()}-"
               f"{obj.contract}-date-nmap-u1000-{obj.analyst} {obj.scope[i].address}")

        # Run the Top 1000 nmap scan (Aggressive) on each IP/domain
        print(f"Nmap scan on {obj.scope[i].address}...\nRunning the Top 1000 nmap scan (Aggressive) on each IP/domain"
              f"...")
        system(f"nmap -A -vv -n -Pn --max-retries 2 --top-ports 1000 -oA {pwd}/{obj.client.replace(' ', '').lower()}-"
               f"{obj.contract}-date-nmap-A1000-{obj.analyst} {obj.scope[i].address}")

        # Run the Top 65K TCP ports for each IP/domain
        # BEWARE!  This could take a long time.  Many clients limit the timeframe of testing for each day.
        print(f"Nmap scan on {obj.scope[i].address}...\nRunning the Top 1000 nmap scan (UDP) on each IP/domain...")
        system(f"nmap -sS -vv -n -Pn --max-retries 2 -p- -oA {pwd}/{obj.client.replace(' ', '').lower()}-"
               f"{obj.contract}-date-nmap-s65K-{obj.analyst} {obj.scope[i].address}")

# Run the function to validate the argument parameters
run_checks(args.client, args.contract, args.scope)

# Create the Scan object
scan = Scan(args.analyst, args.client, args.contract, create_scope(args.scope))

# Run the scans
run_scan(scan)
