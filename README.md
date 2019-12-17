X1027GeoIPWhoISRevDNSVx.x.py by @carlos_cajigas.  
Helps in doing IP geolocation, reverse DNS (if needed) and WhoIs of an IP address, a list of IP addresses, a single host, or a list of hosts.  
The geolocation will be conducted against the Geolite2 database from Maxmind, https://geolite.maxmind.com.  
If the database is not present, the tool will use your internet connection to go and get the latest database.  This only occurs once.  
After the databases has been retrieved the program will close and will need to be rerun.  Subsequent runs of the program will use the existing databases in your current directory.  
If you want a newer database, delete it and the tool will go back out and get the latest one

 
X1027GeoIPWhoISRevDNSVx.x.py by @carlos_cajigas.

optional arguments:
  -h, --help       show this help message and exit
  -i , --ip        specify single ip address
  -if , --ipfile   specify ipfile
  -io , --ipout    ipfile output filename
  -H , --host      specify single host
  -Hf , --hfile    specify hostfile
  -Ho , --hout     hostfile output filename
