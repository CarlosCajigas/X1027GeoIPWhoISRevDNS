"""
Author: Carlos Cajigas @carlos_cajigas 
This program is free software.  You can redistribute
it and/or modify it in any way you desire.

X1027GeoIPMaxmindV#.#.py
    Helps in checking reputation of an ip against Maxmind.  

V0.1 - proof of concept
V0.2 - Added RevDNS
V0.3 - separated into individual definitions
V0.4 - Added resolvehost definition
V0.5 - Added resolvehost write to outfile

"""

import sys
import geoip2.database
from csv import DictWriter
import argparse
import urllib.request
import os
import tarfile
from shutil import copyfile
import requests
from requests.auth import HTTPBasicAuth
from ipwhois import IPWhois
import socket

holder1 = {}

def downloadDb():
	try:
		if os.path.exists('GeoLite2-City.mmdb'):
			sys.exit()

	except Exception as e:
		print ('Something went wrong during the checking of the existing db')
		print (e)

	try:
		print ('Since the GeoLite2 database was not found it will be downloaded now')
		print ('Attempting to download the latest Geolite2 database')
		url = "https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
		urllib.request.urlretrieve(url, "GeoLite2-City.tar.gz")

		print ('Download suceeded')

		print ('Extracting the database from the compressed file into your current directory')

		tar = tarfile.open('GeoLite2-City.tar.gz')
		tar.extractall()
		tar.close()

		#moving the database from the unzipepd dir to the current dir
		curdir = os.getcwd()
		for root,dirs,files in os.walk(curdir):
			if 'GeoLite2-City.mmdb' in files:
				os.path.join(root, 'GeoLite2-City.mmdb')
				copyfile(os.path.join(root, 'GeoLite2-City.mmdb'),os.path.join(curdir, 'GeoLite2-City.mmdb'))

		print ('Extraction succeded')
		print ('The Geolite2 database is now in your current directory and will be used by the program.  Restart the program')
		sys.exit()
		
	except Exception as e:
		print (e)
		print ('Download failed!')
		sys.exit()

def geoip(x):
	try:
		reader = geoip2.database.Reader('GeoLite2-City.mmdb')
		resp = reader.city(x)
		ip = resp.traits.ip_address
		shortcountry = resp.country.iso_code
		longcountry = resp.country.name
		if resp.city.name != None:
			city = resp.city.name
		else:
			city = str('n/a')
		holder1['GEOIP'] = ip
		holder1['GEOCO'] = shortcountry
		holder1['GEOCITY'] = city
		holder1['GEOCOUNTRY'] = longcountry

	except (KeyboardInterrupt):
		sys.exit()	
	except Exception as e:
		holder1['GEOIP'] = x
		holder1['GEOCO'] = str(e)
		holder1['GEOCITY'] = 'error'
		holder1['GEOCOUNTRY'] = 'error'

def geowhois(x):
	try:
		obj = IPWhois(x)
		results = obj.lookup_rdap()
		ip =  results['query']
		country = results['asn_country_code']
		description = results['asn_description']
		cidr = results['asn_cidr']
		date = results['asn_date']
		holder1['WHOISCOUNTRY'] = country
		holder1['WHOISDESC'] = description
		holder1['WHOISCIDR'] = cidr
		holder1['WHOISDATE'] = date
	except (KeyboardInterrupt):
		sys.exit(1)	
	except Exception as e:
		holder1['WHOISCOUNTRY'] = str(e)
		holder1['WHOISDESC'] = 'error'
		holder1['WHOISCIDR'] = 'error'
		holder1['WHOISDATE'] = 'error'

def reversedns(x):
	try:
		reversed_dns = socket.gethostbyaddr(x)
		revdns = reversed_dns[0]
		holder1['REVDNS'] = revdns
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		holder1['REVDNS'] = str(e)

def resolvehost(x):
	try:
		host = (x)
		resolved_host = socket.gethostbyname(x)
		geoip(resolved_host)
		geowhois(resolved_host)
		holder1['HOST'] = host
		holder1['RESHOST'] = resolved_host
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		holder1['HOST'] = (x)
		holder1['RESHOST'] = str(e)
		geoip(x)
		geowhois(x)		

def main():
	parser = argparse.ArgumentParser(description='X1027GeoIPWhoISRevDNSVx.x.py by @carlos_cajigas.  Helps in doing IP geolocation, reverse DNS (if needed) and WhoIs of an IP address, a list of IP addresses, a single host, or a list of hosts.  The geolocation will be conducted against the Geolite2 database from Maxmind, https://geolite.maxmind.com.  If the database is not present, the tool will use your internet connection to go and get the latest database.  This only occurs once.  After the databases has been retrieved the program will close and will need to be rerun.  Subsequent runs of the program will use the existing databases in your current directory.  If you want a newer database, delete it and the tool will go back out and get the latest one.')
	parser.add_argument('-i', '--ip', type=str, metavar='', required=False, help='specify single ip address')
	parser.add_argument('-if', '--ipfile', type=str, metavar='', required=False, help='specify ipfile')
	parser.add_argument('-io', '--ipout', type=str, metavar='', required=False, help='ipfile output filename')
	parser.add_argument('-H', '--host', type=str, metavar='', required=False, help='specify single host')
	parser.add_argument('-Hf', '--hfile', type=str, metavar='', required=False, help='specify hostfile')
	parser.add_argument('-Ho', '--hout', type=str, metavar='', required=False, help='hostfile output filename')
	args = parser.parse_args()

	if os.path.exists('GeoLite2-City.mmdb'):
		pass
	else:
		downloadDb()
	if args.ipfile != None and args.ipout != None:
		ipfile = args.ipfile
		ipout = args.ipout
		ipfile = open(ipfile)
		with open(ipout, 'w', encoding='utf-8', newline='') as resfile:
			fieldnames = ['GEOIP', 'GEOCO', 'GEOCITY', 'GEOCOUNTRY', 'REVDNS', 'WHOISCOUNTRY', 'WHOISDESC', 'WHOISCIDR', 'WHOISDATE']
			csv_writer = DictWriter(resfile, fieldnames=fieldnames)
			csv_writer.writeheader()
			for line in ipfile.readlines():
				ip = line.strip("\n")
				geoip(ip)
				geowhois(ip)
				reversedns(ip)
				sentence = '{GEOIP} from {GEOCITY},{GEOCOUNTRY} {REVDNS}. Desc is {WHOISDESC} from {WHOISCOUNTRY}'.format(**holder1)
				print(sentence)
				csv_writer.writerow(holder1)
		print("")
		print('Data saved to ' + ipout)

	if args.hfile != None and args.hout != None:
		hfile = args.hfile
		hout = args.hout
		hfile = open(hfile)
		with open(hout, 'w', encoding='utf-8', newline='') as resfile:
			fieldnames = ['HOST', 'RESHOST', 'GEOCITY', 'GEOCOUNTRY', 'WHOISCOUNTRY', 'WHOISDESC', 'WHOISCIDR', 'WHOISDATE']
			csv_writer = DictWriter(resfile, fieldnames=fieldnames)
			csv_writer.writeheader()
			for line in hfile.readlines():
				host = line.strip("\n")
				resolvehost(host)
				del holder1['GEOIP']
				del holder1['GEOCO']
				sentence = '{HOST} resolved to {RESHOST} from {GEOCITY},{GEOCOUNTRY}. Desc is {WHOISDESC} from {WHOISCOUNTRY}'.format(**holder1)
				#sentence = '{HOST} from {RESHOST}'.format(**holder1)
				print(sentence)
				csv_writer.writerow(holder1)
		print("")
		print('Data saved to ' + hout)

	elif args.hfile != None:
		hfile = args.hfile
		hout = args.hout
		hfile = open(hfile)
		for line in hfile.readlines():
			host = line.strip("\n")
			resolvehost(host)
			sentence = '{HOST} resolved to {RESHOST} from {GEOCITY},{GEOCOUNTRY}. Desc is {WHOISDESC} from {WHOISCOUNTRY}'.format(**holder1)
			print(sentence)
		print("")
		print('output was printed to screen only')
		print('save the data to a csvfile with -Ho option')	
	
	elif args.ipfile != None:
		ipfile = args.ipfile
		ipfile = open(ipfile)
		for line in ipfile.readlines():
			ip = line.strip("\n")
			geoip(ip)
			geowhois(ip)
			reversedns(ip)
			sentence = '{GEOIP} from {GEOCITY},{GEOCOUNTRY} {REVDNS}. Desc is {WHOISDESC} from {WHOISCOUNTRY}'.format(**holder1)
			print(sentence)
		print("")
		print('output was printed to screen only')
		print('save the data to a csvfile with -io option')	

	elif args.ip != None:
		ip = args.ip
		geoip(ip)
		geowhois(ip)
		reversedns(ip)
		sentence = '{GEOIP} from {GEOCITY},{GEOCOUNTRY}\nReverseDNS {REVDNS}\nWhoIs {WHOISDESC} from {WHOISCOUNTRY}'.format(**holder1)
		print(sentence)
	
	elif args.host != None:
		host = args.host
		resolvehost(host)
		sentence = '{HOST} = {RESHOST} from {GEOCITY},{GEOCOUNTRY}\nWhoIs {WHOISDESC} from {WHOISCOUNTRY}'.format(**holder1)
		print(sentence)

	else:
		print('try again')

if __name__ == '__main__':
	main()
