#!/usr/bin/python
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------------------------#
"""
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


V0.1 - proof of concept
V0.2 - added the ability to download the geolite2 database, if not found in the current directory
V0.3 - improved output to not have less empty fields.  
V1.3 - All results in one line
V2.1 - This is an improvement of the X1027GeoIPAndReverseDNS after also adding a WhoIs check
V3.1 - This is an improvement of the X1027GeoIPAndReverseDNSBlacklist after also adding a Blacklist check
V3.2 - Replaced optparse for argparse and added single IP parsing option
V3.3 - Improved the geoiprevDns function to now print more data to screen when used with the -i flag
V3.4 - Added the ability to do host resolution and chaged the CLI flags
"""

import socket
import sys
import argparse
import geoip2.database
import urllib2
import os
import tarfile
import zipfile
from shutil import copyfile
from ipwhois import IPWhois
import warnings
warnings.filterwarnings("ignore")

data = []
blacklistdata = []

#this is a definition that takes the ips from passed file and uniques them and adds them to the data list
def uniqdata(x):
	log = open(x)
	for line in log.readlines(): 
		line = line.strip('\n')
		if line not in data:
			data.append(line)

#this is a definition that grabs the blacklist database and adds it to the blacklistdata list
def loadblacklist():
	blacklist = "full_blacklist_database.txt"
	with open(blacklist) as file:
		for line in file.readlines():
			line = line.split("\t")
			blacklistdata.append(line[0])

#this is a definition that is responsible to downloading the Geolite2 database needed by the tool
def downloadDb():
	try:
#This checks to see if the database is present in the current directory
		if os.path.exists('GeoLite2-City.mmdb'):
			sys.exit()
	except Exception as e:
		print "Something went wrong during the checking of the existing db"
		print e

	try:
#if the database is not found this definition will go out and get it
		print "Since the GeoLite2 database was not found it will be downloaded now"
		print "Attempting to download the latest Geolite2 database"
		url = urllib2.urlopen("https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz")
		geofile = url.read()
#this writes the database to the current directory
		with open('GeoLite2-City.tar.gz','wb') as file:
			file.write(geofile)
		print "Download suceeded."
		print "Extracting the database from the compressed file into your current directory"

#The database is in gz format so it has to be decompressed.  This does it
		tar = tarfile.open('GeoLite2-City.tar.gz')
		tar.extractall()
		tar.close()

#after being decompressed, the database needs to be moved to the current dir, I chose to do a copy instead
		curdir = os.getcwd()
		for root,dirs,files in os.walk(curdir):
			if 'GeoLite2-City.mmdb' in files:
				os.path.join(root, 'GeoLite2-City.mmdb')
#this is the copy command
				copyfile(os.path.join(root, 'GeoLite2-City.mmdb'),os.path.join(curdir, 'GeoLite2-City.mmdb'))
		print "Extraction succeded." 
		print "The Geolite2 database is now in your currently and will be used by the program.  Restart the program."
		sys.exit()

	except Exception as e:
		print e
		print "Download failed!"
		sys.exit()

#this is a definition that is responsible for downloading the blacklist database from myip.ms that is needed by the tool
#it uses just about the same logic as the previous definition so I am not commenting it.  
def downloadblackDb():
	try:
		if os.path.exists('full_blacklist_database.txt'):
			sys.exit()

	except Exception as e:
		print "Something went wrong during the checking of the existing db"
		print e

	try:
		print "Since the myip.ms blacklist database was not found it will be downloaded now"
		print "Attempting to download the latest full myip.ms blacklist database.  \nThis is the last database that we will downloaded"
		url = urllib2.urlopen("https://myip.ms/files/blacklist/general/full_blacklist_database.zip")
		blacklistfile = url.read()
		with open('full_blacklist_database.zip','wb') as file:
			file.write(blacklistfile)
		print "Download suceeded."
		print "Extracting the database from the compressed file into your current directory"

		with zipfile.ZipFile('full_blacklist_database.zip', 'r') as zip:
			zip.extractall()
		print "Extraction succeded." 
		print "The full blacklist database is now in your currently and will be used by the program.  Restart the program."
		sys.exit()

	except Exception as e:
		print e
		print "Download failed!"
		sys.exit()


def geoiprevDns(x):
#this is a very long definition.  It was designed to do the four checks.  
#this first try and except will grap the ip address and will check it aginst the maxmind database.  
	try:
#i decided to insert all results to one list called holder so that when I print the list, all results are in one line
		holder = []
#variable that is assigned to the geoip2 module for reading
		reader = geoip2.database.Reader('GeoLite2-City.mmdb')
#the variable assigned to the response
		resp = reader.city(x)
#variable that returns the ip address
		ip = resp.traits.ip_address
#this inserts the variable into placeholder 0 on the list 
		holder.insert(0,ip)
#variable assigned to the abbreviated country 
		shortcountry = resp.country.iso_code
#this inserts the variable into placeholder 1 on the list 
		holder.insert(1,shortcountry)
#variable assigned to the longcountry
		longcountry = resp.country.name
#this inserts the variable into placeholder 2 on the list 
		holder.insert(2,longcountry)
#this inserts the string OK into placeholder 4 on the list so that it can be part of the results
		holder.insert(4,"OK")
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
#the below crap has to be done so that when the ip is not in the maxmind geoIP database we can gracefully catch and print the error message
		geoerror = str('error - ' + str(e))
		ip = (x)
		holder.insert(0,ip)
		holder.insert(1,"error")
		holder.insert(2,"error")
		holder.insert(4,geoerror)

#this following try and except is responsible for conducting the reverse dns check of each ip
#address after the GeoIP check has finished.
	try:
#this will grab each IP from the ipfile and conduct reverse DNS
		reversed_dns = socket.gethostbyaddr(x)
		revdns = reversed_dns[0]
#this inserts the variable into placeholder 3 on the list
		holder.insert(3,revdns)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
#the below crap has to be done so that when the ip does not have reverse DNS information we can gracefully catch and print the error message
		revdnserror = str('error - ' + str(e))
		holder.insert(3,revdnserror)

#this following try and except is responsible for doing the check against WhoIs
	try:
#variable that is assigned to the geoip2 module for reading		
		obj = IPWhois(x)
#the results of the read		
		results = obj.lookup_rdap()
#this is a variable assigned to the ip, but is not printed
		x =  results['query']
#variable that is assigned to the country		
		whoiscountry = results['asn_country_code']
		holder.insert(5,whoiscountry)
#variable that is assigned to the description provided by whois
		whoisdescription = results['asn_description']
		holder.insert(6,whoisdescription)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		ipwhoiserror = str('error - ' + str(e))
		holder.insert(5,ipwhoiserror)
		holder.insert(6,"error")

#this following try and except is responsible for doing the check against the blacklist database from myip.ms
	try:
#if the ip is in the blacklist database, you get the link from myip.ms for more information
		if x in blacklistdata:
			#print x + '|' + "http://blacklist.myip.ms/" + x
			inblacklist = "http://blacklist.myip.ms/" + x
			holder.insert(7,inblacklist)
#if the IP is not in the blacklist database it will still print no in list
		else:
			# print x + '|' + "not in list"
			notinblacklist = "not in list"
			holder.insert(7,notinblacklist)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		print (x) + '|' + 'error - ' + str(e)


#this prints all of the data that was inserted into the list into one pretty harmonious line.  hell yeah!
	print "|".join(holder)

#this is pretty much the same definition as above.  The only difference is the print statements at the 
#end of the definition.  It is only used to parse a single IP address
#passed to the tool via the "-i" flag.  If the user passes a list of addresses with the "-if " flag 
#this definition will not be used, instead the above definition will be used. 
def geoiprevDnssingle(x):
	try:
		holder = []
		reader = geoip2.database.Reader('GeoLite2-City.mmdb')
		resp = reader.city(x)
		ip = resp.traits.ip_address
		holder.insert(0,ip)
		shortcountry = resp.country.iso_code
		holder.insert(1,shortcountry)
		longcountry = resp.country.name
		holder.insert(2,longcountry)
		holder.insert(4,"OK")
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		geoerror = str('error - ' + str(e))
		ip = (x)
		holder.insert(0,ip)
		holder.insert(1,"error")
		holder.insert(2,"error")
		holder.insert(4,geoerror)

	try:
		reversed_dns = socket.gethostbyaddr(x)
		revdns = reversed_dns[0]
		holder.insert(3,revdns)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		revdnserror = str('error - ' + str(e))
		holder.insert(3,revdnserror)

	try:
		obj = IPWhois(x)
		results = obj.lookup_rdap()
		x =  results['query']
		whoiscountry = results['asn_country_code']
		holder.insert(5,whoiscountry)
		whoisdescription = results['asn_description']
		holder.insert(6,whoisdescription)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		#print x + '|' + 'error ' + str(e)
		ipwhoiserror = str('error - ' + str(e))
		holder.insert(5,ipwhoiserror)
		holder.insert(6,"error")

	try:
		if x in blacklistdata:
			#print x + '|' + "http://blacklist.myip.ms/" + x
			inblacklist = "http://blacklist.myip.ms/" + x
			holder.insert(7,inblacklist)
		else:
			# print x + '|' + "not in list"
			notinblacklist = "not in list"
			holder.insert(7,notinblacklist)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		print (x) + '|' + 'error - ' + str(e)


#this is the only difference in the definition.  Rather than using the "print "|".join(holder)" to print 
#the data, I did the below.  If you want this infotmation in a CSV, put the IP in a file and 
#give it to the tool via the -if flag.
	print "IP = " + holder[0]
	print "GEOIPCO = " + holder[1]
	print "GEOIPCOUNTRY = " + holder[2]
	print "REVERSEDNS = " + holder[3]
	print "OKorNotIGEOIPdb = " + holder[4]
	print "WhoIsCOUNTRY = " + holder[5]
	print "WhoIsDESCRIPTION = " + holder[6]
	print "InBLACKLIST = " + holder[7]

#the below definition was created so that when a user provides a list of hostnames this definition 
#will glab each host from the file and will pass it one at a time to resolve the host to an IP address.
#after resolving the host to an IP address, the IP will be geolocated, checked against whoit and also
#checked against the blacklist database.   
def resolvehost(x):
	try:
#just like before I decided to place all of the data that the definition returns inside of a list called holder
		holder = []
#this resolves the host to an IP address
		resolved_host = socket.gethostbyname(x)
#the host is assigned a variable
		host = x
#inserting into a place holder.  As you can see my code is repetitive 
		holder.insert(0,host)
		holder.insert(1,resolved_host)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		host = x
		holder.insert(0,host)
		resolveerror = str('error - ' + str(e))
		holder.insert(1,resolveerror)
		holder.insert(2,"did not resolve")
		holder.insert(3,"did not resolve")
		holder.insert(4,"did not resolve")
		holder.insert(5,"did not resolve")
		holder.insert(6,"did not resolve")

#this is the geoIP check
	try:
		reader = geoip2.database.Reader('GeoLite2-City.mmdb')
		resp = reader.city(resolved_host)
		ip = resp.traits.ip_address
		shortcountry = resp.country.iso_code
		holder.insert(2,shortcountry)
		longcountry = resp.country.name
		holder.insert(3,longcountry)
	except (KeyboardInterrupt):
		sys.exit()
	except:
		pass

#this is the WhoIS check
	try:
		obj = IPWhois(resolved_host)
		results = obj.lookup_rdap()
		#x =  results['query']
		whoiscountry = results['asn_country_code']
		holder.insert(4,whoiscountry)
		whoisdescription = results['asn_description']
		holder.insert(5,whoisdescription)
	except (KeyboardInterrupt):
		sys.exit()
	except:
		pass

#this is the blacklist check
	try:
		if resolved_host in blacklistdata:
			#print x + '|' + "http://blacklist.myip.ms/" + x
			inblacklist = "http://blacklist.myip.ms/" + resolved_host
			holder.insert(6,inblacklist)
		else:
			notinblacklist = "not in list"
			holder.insert(6,notinblacklist)
	except (KeyboardInterrupt):
		sys.exit()
	except:
		pass
	print "|".join(holder)

#this is pretty much the same definition as above.  The only difference is the print statements at the 
#end of the definition.  It is only used to parse a single host
#passed to the tool via the "-H" flag.  If the user passes a list of hosts with the "-Hf " flag 
#this definition will not be used, instead the above definition will be used. 
def resolvehostsingle(x):
	try:
		holder = []
		resolved_host = socket.gethostbyname(x)
		host = x
		holder.insert(0,host)
		holder.insert(1,resolved_host)
	except (KeyboardInterrupt):
		sys.exit()
	except Exception as e:
		host = x
		holder.insert(0,host)
		resolveerror = str('error - ' + str(e))
		holder.insert(1,resolveerror)
		holder.insert(2,"did not resolve")
		holder.insert(3,"did not resolve")
		holder.insert(4,"did not resolve")
		holder.insert(5,"did not resolve")
		holder.insert(6,"did not resolve")

	try:
		reader = geoip2.database.Reader('GeoLite2-City.mmdb')
		resp = reader.city(resolved_host)
		ip = resp.traits.ip_address
		shortcountry = resp.country.iso_code
		holder.insert(2,shortcountry)
		longcountry = resp.country.name
		holder.insert(3,longcountry)
	except (KeyboardInterrupt):
		sys.exit()
	except:
		pass

	try:
		obj = IPWhois(resolved_host)
		results = obj.lookup_rdap()
		#x =  results['query']
		whoiscountry = results['asn_country_code']
		holder.insert(4,whoiscountry)
		whoisdescription = results['asn_description']
		holder.insert(5,whoisdescription)
	except (KeyboardInterrupt):
		sys.exit()
	except:
		pass

	try:
		if resolved_host in blacklistdata:
			#print x + '|' + "http://blacklist.myip.ms/" + x
			inblacklist = "http://blacklist.myip.ms/" + resolved_host
			holder.insert(6,inblacklist)
		else:
			notinblacklist = "not in list"
			holder.insert(6,notinblacklist)
	except (KeyboardInterrupt):
		sys.exit()
	except:
		pass
#this is the only difference in the definition from the above.  Rather than using the "print "|".join(holder)" to print 
#the data, I did the below.  If you want this infotmation in a CSV, put the host in a file and 
#give it to the tool via the -Hf flag.
	print "HOST = " + holder[0]
	print "IP = " + holder[1]
	print "GEOIPCO = " + holder[2]
	print "GEOIPCOUNTRY = " + holder[3]
	print "WhoIsCOUNTRY = " + holder[4]
	print "WhoIsDESCRIPTION = " + holder[5]
	print "InBLACKLIST = " + holder[6]


def main():
#command line parameter options. 
	parser = argparse.ArgumentParser(description='X1027GeoIPRevDNSWhoISBlacklist.py by @carlos_cajigas.  Helps in doing IP geolocation, reverse DNS (if needed), WhoIs and a blacklist check of an IP address, a list of IP addresses, a single host, or a list of hosts.  This program can get you information about an IP address or a host by its name.  It was designed to do four checks.  It will do geolocation, a reverse DNS check (if needed), it will query whois and will check your IP or host against a blacklist database.  If you provide a list of IPs, the checks will be conducted after the IP addresses in your file are sorted and uniqued.  The geolocation will be conducted against the Geolite2 database from Maxmind, https://geolite.maxmind.com.  The blacklist checks will be conducted against the full list from https://myip.ms/ If the databases are not present, the tool will use your internet connection to go and get the latest databases.  This only occurs once.  After the databases has been retrieved the program will close and will need to be rerun.  Subsequent runs of the program will use the existing databases in your current directory.  If you want newer databases, delete them and the tool will go back out and get the latest ones.')
#this is the CLI parameter for a single ip address
	parser.add_argument('-i', '--ip', type=str, metavar='', help='specify ip address')
#this is the CLI parameter for a file containing a list of IP addresses
	parser.add_argument('-if', '--ifile', type=str, metavar='', help='specify ip file')
#this is the CLI parameter for a single host
	parser.add_argument('-H', '--host', type=str, metavar='', help='specify host')
#this is the CLI parameter for a file containing a list of hosts
	parser.add_argument('-Hf', '--hfile', type=str, metavar='', help='specify hosts file')
	args = parser.parse_args()

# we are in the main fucntion now.  This checks for the database in the current 
# directory if the file is present it just passes and moves on to the specific section
# to parse a file or a single IP address.  if the database is not present then it executes 
# the downloadDb fucntion, which downloads the database and exits.  pretty neat, right???
	if os.path.exists('GeoLite2-City.mmdb'):
		pass
	else:
		downloadDb()	
	if os.path.exists('full_blacklist_database.txt'):
		pass
	else:
		downloadblackDb()	
#this if statement will be run if the user provided a single IP address
	if args.ip != None:
		ip = args.ip
		loadblacklist()
		geoiprevDnssingle(ip)
#this if statement will be run if the user provided a file with IPs
	if args.ifile != None:
		ipfile = args.ifile
# this takes the ipfile and sends it to the uniqdata definition that sorts and uniques it and then
# adds the data to the data empty list
		uniqdata(ipfile)
		loadblacklist()
#this just simply print the header of the pipe delimited file
		print 'IP|GEOIPCO|GEOIPCOUNTRY|REVERSEDNS|OKorNotIGEOIPdb|WhoIsCOUNTRY|WhoIsDESCRIPTION|InBLACKLIST'
#for loop that take one ip at a time from the data list and sends it through the geoiprevDns definition
		for ip in sorted(data):
			geoiprevDns(ip)
#this if statement will be run if the user provided a single host 	
	if args.host != None:
		host = args.host
		loadblacklist()
		resolvehostsingle(host)
#this if statement will be run if the user provided a file with hosts
	if args.hfile != None:
		hostsfile = args.hfile
	#assisgn the command line parameter as the file to open
		hostsfile = open(hostsfile)#args.file)
		loadblacklist()
		#for loop that take one line at a time and sends it through the function
		print 'HOST|IP|GEOIPCO|GEOIPCOUNTRY|WhoIsCOUNTRY|WhoIsDESCRIPTION|InBLACKLIST'
		for line in hostsfile.readlines():
			host = line.strip("\n")
			resolvehost(host)

if __name__ == '__main__':
	main()