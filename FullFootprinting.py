#!/usr/bin/env python
#-*- coding:utf-8 -*-

try:
	import nmap
	import sys
	import socket 
	import re
	import os
	import argparse
	import theHarvester
	import urllib2
	import whois 
    

		
except ImportError,e:
	import sys
	sys.stdout.write("%s\n" %e)
	sys.exit(1)
 
 
 
class Tarama:
	def __init__(self):
		self.cmd_arg = "-n -Pn -sS -sV -T4 --top-ports 10"
		self.nmap_services_file = "/usr/share/nmap/nmap-services"
		self.nm = nmap.PortScanner()
 
	def get_service_name(self, port, proto):
		nmap_file = open(self.nmap_services_file,"r")
		service = ""
		for line in nmap_file:
				if re.search("([^\s]+)\s%d/%s\s"% (port, proto), line):
					service = re.search("([^\s]+)\s%d/%s\s"% (port, proto), line).groups(1)[0]
					break
		return service
 
 
	def run_scan(self,targets):
		self.nm.scan(hosts = "%s"% targets, arguments = "%s"% self.cmd_arg)
		
		
		for host in self.nm.all_hosts():
			print "IP i ADRESİNİZ",host
			print "\n"
			print("PORT     STATE     SERVICE")
			for proto in self.nm[host].all_protocols():
				result = self.nm[host][proto].keys()
				result.sort()
				
				for port in result:
						res = str(port) + "/" + proto
						space = str(" " * (9 - len(res)))
						service = self.get_service_name(port, proto)
						state = self.nm[host][proto][port]['state']
						space2 = str(" " * (10 - len(state)))
						print "%s/%s%s%s%s%s" % (port,proto,space,state,space2,service)
						
						 
	          # WHOİS #    
						   
def perform_whois(server , query) :
   
    s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    s.connect((server , 43))
    s.send(query + '\r\n')
     
    
    msg = ''
    while len(msg) < 10000:
        chunk = s.recv(100)
        if(chunk == ''):
            break
        msg = msg + chunk
     
    return msg

def get_whois_data(domain_name):
     
    
    domain_name = domain_name.replace('http://','')
    domain_name = domain_name.replace('www.','')
     
    ext = domain_name[-3:]
     
   
    if(ext == 'com' or ext == 'org' or ext == 'net'):
        whois = 'whois.internic.net'
        msg = perform_whois(whois , domain_name)
         
       
        lines = msg.splitlines()
        for line in lines:
            if ':' in line:
                words = line.split(':')
                if  'Whois' in words[0] and 'whois.' in words[1]:
                    whois = words[1].strip()
                    break;
     
    
    else:
        ext = domain_name.split('.')[-1]
         
       
        whois = 'whois.iana.org'
        msg = perform_whois(whois , ext)
         
       
        lines = msg.splitlines()
        for line in lines:
            if ':' in line:
                words = line.split(':')
                if 'whois.' in words[1] and 'Whois Server (port 43)' in words[0]:
                    whois = words[1].strip()
                    break;
     
    msg = perform_whois(whois , domain_name)
    return msg
    
print "Adresi girerken başına www. Kullanmayınız."
domain_name = raw_input("Domain adresi=")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Nmap Ile Port Tarama Programi')
	try:
			tarama = Tarama()
			tarama.run_scan(domain_name)
	except Exception, e:
			print >> sys.stderr, "Hata: %s"% e
			sys.exit(2) 


			
		#HTTP FINGERPRINTING SCRIPT
print(" \n \n ***** HTTP Banner Grabbing ***** \n")
remoteServer2="http://www."+domain_name
c = urllib2.urlopen(remoteServer2)
print c.info()
print c.getcode()


			
	#Harvester#
print(" \n \n ***** Harvester ***** \n")
sorgu='-d '+ domain_name + ' -b google -l 100'
sorgu=sorgu.split()
sonuc=theHarvester.start(sorgu)
for emails in sonuc:
        print emails
        
print(" \n \n ***** WHOİS***** \n")
print get_whois_data(domain_name)

						
						

 

      

        
	


