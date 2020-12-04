#!/usr/bin/python3
from argparse import ArgumentParser
from re import compile, match
from os import getcwd
from getpass import getuser

pwd = getcwd()
regex_name = compile(f"^[A-Za-z].*\s[A-Za-z].*$")
regex_contract = compile("^[0-9]{8}$")
regex_ip4 = compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4]"
                    "[0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
regex_domain = compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]")

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


class Scan:
    def __init__(self, analyst, client, contract, scope=None):
        self.analyst = str(analyst)
        self.client = str(client)
        self.contract = str(contract)
        self.scope = scope


class Asset:
    def __init__(self):
        self.address = str()

    def add(self, address):
        if address is None:
            raise Exception(f"You must provide an IP or URL.")
        elif match(regex_ip4, address) or match(regex_domain, address):
            self.address = str(address)


def run_checks(client, contract, scope):
    if client is None:
        raise Exception(f"You must provide a client name.")
    elif contract is None:
        raise Exception(f"You must provide a contract number.")
    elif scope is None:
        raise Exception(f"You must provide a scope file.")
    else:
        pass


def create_scope(scope):
    obj_list = list()
    with open(scope, 'r') as f:
        scope_list = [x.strip() for x in f.readlines()]

    for i in scope_list:
        tmp_asset = Asset()
        tmp_asset.add(i)
        obj_list.append(tmp_asset)

    return obj_list


run_checks(args.client, args.contract, args.scope)
scan = Scan(args.analyst, args.client, args.contract)
a = create_scope(args.scope)



