#!/usr/bin/env python
#-*- coding:utf-8 -*-

try:
	import sys
	import socket
	import re
	import os
	import urllib2
	import whois
	import socket




except ImportError,e:
	import sys
	sys.stdout.write("%s\n" %e)
	sys.exit(1)



print "Adresi girerken başına www. Kullanmayınız."
domain_name = raw_input("Domain adresi=")


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



print(" \n \n ***** HTTP Banner Grabbing ***** \n")
remoteServer2="http://www."+domain_name
c = urllib2.urlopen(remoteServer2)
print c.info()
print c.getcode()


print(" \n \n ***** WHOİS***** \n")
print get_whois_data(domain_name)

