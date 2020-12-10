#!/usr/bin/python3
from argparse import ArgumentParser
from datetime import date
from re import compile, match
from os import getcwd, system, listdir, path
from getpass import getuser

pwd = getcwd() # Get the present working directory
regex_name = compile(f"^[A-Za-z].*\s[A-Za-z].*$") # Regex for first and last names
regex_contract = compile("^[0-9]{8}$") # Regex for client contract numbers
regex_ip4 = compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4]"
                    "[0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") # Regex for IPv4
regex_ip6 = compile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:"
                    "[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:"
                    "[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}"
                    "(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)"
                    "|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1"
                    "{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:"
                    "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
regex_domain = compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]") # Domain regex
regex_cidr = compile("^(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}"
                     "(/(3[012]|[12]\d|\d))$") # Regex for IPv4 CIDR
scan_types = ['t1000', 'u1000', 'a1000', 's65K']
today = date.today()

# Create the argument parser and add argument parameters
parser = ArgumentParser(description='Run a short nmap scan.')
parser.add_argument('--analyst', action='store', help='Enter the name of the analyst (e.g. John Smith).', type=str,
                    dest='analyst', default=getuser())
parser.add_argument('--client', action='store', help='Enter the name of the client (e.g. Evil Corp).', type=str,
                    dest='client', default=None)
parser.add_argument('--contract', action='store', help='Enter the contract number (e.g. 20081101).', type=str,
                    dest='contract', default=None)
parser.add_argument('--scope', action='store',
                    help='Enter the filepath of the file that contains the list of IPs/URLs (e.g. /path/to/file)',
                    type=str, dest='scope', default=None)
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
        elif match(regex_ip4, address) or match(regex_domain, address) or match(regex_ip6, address)\
                or match(regex_cidr, address):
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


def run_scan(obj: object, scan_type):
    # Run the Top 1000 nmap scan (SYN) on each IP/domain
    if scan_type == 't1000':
        system(f"nmap -sS -vv -n -Pn --max-retries 2 --top-ports 1000 -iL {args.scope} -oA {pwd}/"
               f"{obj.client.replace(' ', '').lower()}-{obj.contract}-{today.strftime('%Y%m%d')}-nmap-{scan_type}-"
               f"{obj.analyst}")

    # Run the Top 1000 nmap scan (UDP) on each IP/domain
    elif scan_type == 'u1000':
        system(f"nmap -sU -vv -n -Pn --max-retries 2 --top-ports 1000 -iL {args.scope} -oA {pwd}/"
               f"{obj.client.replace(' ', '').lower()}-{obj.contract}-{today.strftime('%Y%m%d')}-nmap-{scan_type}-"
               f"{obj.analyst}")

    # Run the Top 1000 nmap scan (Aggressive) on each IP/domain
    elif scan_type == 'a1000':
        system(f"nmap -A -vv -n -Pn --max-retries 2 --top-ports 1000 -iL {args.scope} -oA {pwd}/"
               f"{obj.client.replace(' ', '').lower()}-{obj.contract}-{today.strftime('%Y%m%d')}-nmap-{scan_type}-"
               f"{obj.analyst}")

    # Run the Top 65K TCP ports for each IP/domain
    # BEWARE!  This could take a long time.  Many clients limit the timeframe of testing for each day.
    elif scan_type == 's65K':
        system(f"nmap -sS -vv -n -Pn --max-retries 2 -p- -iL {args.scope} -oA {pwd}/"
               f"{obj.client.replace(' ', '').lower()}-{obj.contract}-{today.strftime('%Y%m%d')}-nmap-{scan_type}-"
               f"{obj.analyst}")

    else:
        raise Exception(f"Scan type '{scan_type}' is invalid.")


def do_scans(obj: object):
    [run_scan(obj, x) for x in scan_types]


def convert_xsl():
    files = [f for f in listdir(f'{pwd}') if path.isfile(f)]
    for f in files:
        if f[-4:] == ".xml":
            system(f"xsltproc {f} -o {pwd}/{f[:-4]}.html")


# Run the function to validate the argument parameters
run_checks(args.client, args.contract, args.scope)

# Create the Scan object
scan = Scan(args.analyst, args.client, args.contract, create_scope(args.scope))

# Run the scans
do_scans(scan)
convert_xsl()
