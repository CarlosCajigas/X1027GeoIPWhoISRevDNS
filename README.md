# X1027GeoIPRevDNSWhoISBlacklist
A python script that helps in doing IP geolocation, reverse DNS (if needed), a WhoIs check and a blacklist check of an IP address, a list of IP addresses, a single host, or a list of hosts

Author: Carlos Cajigas @carlos_cajigas 
This program is free software.  You can redistribute
it and/or modify it in any way you desire.  This program can get you 
information about an IP address or a host by its name.  It was 
designed to do four checks.  It will do geolocation, a reverse DNS check (if needed), 
it will query whois and will check your IP or host against a blacklist database.
If you provide a list of IPs, the checks will be conducted after the IP addresses in your
file are sorted and uniqued.  The geolocation will be conducted against
the Geolite2 database from Maxmind, https://geolite.maxmind.com.
The blacklist checks will be conducted against the full list from https://myip.ms/
If the databases are not present, the tool will use your internet connection
to go and get the latest databases.  This only occurs once.  After the 
databases has been retrieved the program will close and will need to be 
rerun.  Subsequent runs of the program will use the existing databases
in your current directory.  If you want newer databases, delete them and 
the tool will go back out and get the latest ones.

 
X1027GeoIPRevDNSWhoISBlacklist#.#.py
	Helps in doing IP geolocation, reverse DNS (if needed), WhoIs and a blacklist check of
	an IP address, a list of IP addresses, a single host, or a list of hosts
	optional arguments:
	-h, --help      show this help message and exit
	-i , --ip       specify ip address
	-if , --ifile   specify ip file
	-H , --host     specify host
	-Hf , --hfile   specify hosts file
