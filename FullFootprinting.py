#!/usr/bin/env python
#-*- coding:utf-8 -*-

try:
	import sys
	import socket
	import re
	import os
	import urllib2




except ImportError,e:
	import sys
	sys.stdout.write("%s\n" %e)
	sys.exit(1)



print "Adresi girerken başına www. Kullanmayınız."
domain_name = raw_input("Domain adresi=")


		#HTTP FINGERPRINTING SCRIPT
print(" \n \n ***** HTTP Banner Grabbing ***** \n")
remoteServer2="http://www."+domain_name
c = urllib2.urlopen(remoteServer2)
print c.info()
print c.getcode()
