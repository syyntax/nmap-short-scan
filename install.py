from os import system, path
from shutil import copyfile

# Setup the man page
src = path.dirname(path.abspath(__file__))
dst = '/usr/share/man/man8'

copyfile(f"{path.abspath('nmap-short-scan.8')}", '/usr/share/man/man8/nmap-short-scan.8')
system(f"gzip -f /usr/share/man/man8/nmap-short-scan.8")
copyfile(f"{src}/nmap-short-scan.py", f"/usr/local/bin/nmap-short-scan")
system('sudo chmod +x /usr/local/bin/nmap-short-scan')

print("Complete.\n")
