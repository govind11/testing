#! /usr/bin/python

import xml.sax, ConfigParser, os, commands
from dbCommands import Database

class endpointHandler(xml.sax.ContentHandler):
	def __init__(self, osInfo):
		self.count = 0
		self.osCount = ""
		self.osInfo = osInfo
		self.CurrentData = ""
		self.ipAddr = None
		self.macAddr = None
		self.vendor = None
		self.os = None
		self.domain = None
		self.status = None
		self.osflag = False

	def startElement(self, tag, attributes):
		self.CurrentData = tag
		
		if self.CurrentData == 'host':
			# create the new entry in osInfo
			self.count += 1
			self.osCount = 'os_' + str(self.count)
			self.osInfo[self.osCount] = {}

		if self.CurrentData == 'status':
			self.status = attributes['state']
			self.osInfo[self.osCount]['status'] = self.status
		if self.CurrentData == 'address':
			addressType = attributes['addrtype']
			if addressType == 'ipv4':
				self.ipAddr = attributes['addr']
				self.osInfo[self.osCount]['ipAddr'] = self.ipAddr
			elif addressType == 'mac':
				# print "attributes***************", attributes.keys()
				attrKeys = ['addr', 'vendor', 'macAddr']
				self.macAddr = attributes['addr']
				if 'vendor' in attributes.keys():
					self.vendor = attributes['vendor']
				else:
					self.vendor = "Not Found"
				self.osInfo[self.osCount]['macAddr'] = self.macAddr
				self.osInfo[self.osCount]['vendor'] = self.vendor

		if self.CurrentData == 'elem':
			value = attributes['key']
			if value == 'os':
				self.os = "self.os"
				self.osflag = True
			if value == 'lanmanager' and self.osflag == False:
				self.os = "self.os"
			if value == 'domain_dns':
				self.domain = "self.domain"
			if value == 'domain':
				self.domain = "self.domain"


	def characters(self, content):
		if self.CurrentData == 'elem' and self.os == "self.os":
			self.os = content
			self.osInfo[self.osCount]['os'] = self.os
			self.os = ""
		if self.CurrentData == 'elem' and self.domain == "self.domain":
			self.domain = content
			self.osInfo[self.osCount]['domain'] = self.domain
			self.domain = ""

def osDiscovery():
	"""performs the smb scan for the given ip range.
	this is to detect the OS."""
	import os
	osInfo = {}
	config = ConfigParser.RawConfigParser()
	config.read('rootConfig.cfg')
	password = config.get('rootInfo', 'password')
	db = Database()

	osMap = {
        "Windows XP (Windows 2000 LAN Manager)" : "Windows XP",
        "Windows 5.1" : "Windows XP",
        "Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)" : "Windows 7 Service Pack 1",
        "Windows 7 Professional 7601 Service Pack 1" : "Windows 7 Service Pack 1",
        "Windows 8.1 Pro 9600 (Windows 8.1 Pro 6.3)" : "Windows 8.1",
        "Windows 8.1 Pro 9600" : "Windows 8.1",
        "Windows 10 Enterprise 10240 (Windows 10 Enterprise 6.3)" : "Windows 10",
        "Windows 10 Enterprise 10240" : "Windows 10",
        "Windows 10 Pro 10586 (Windows 10 Pro 6.3)" : "Windows 10",
        "Windows 10 Pro 10586" : "Windows 10",
        "Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)" : "Windows Server 2012 R2",
        }

	for i in range(0, 255):
		iprange = '192.168.%s.0/24' % str(i) #192.168.15.0/24
		cmd = "echo '%s' | sudo -S nmap -sU -sS -oX -  --script smb-os-discovery.nse -p U:137,T:139 %s" % (password, iprange) + " > " + "/".join([os.getcwd(),'osDiscovery.xml'])
		# cmd = "echo '%s' | sudo -S nmap -n -p137,138,139,445 -oX -  --script smb-os-discovery.nse %s" % (password, iprange) + " > " + "/".join([os.getcwd(),'osDiscovery.xml'])
		(status, output) = commands.getstatusoutput(cmd)
		if status == 0:
			print "OS Discovery Scan Completed for iprange %s" % iprange
		else:
			print "Could Not finish OS Discovery Scan."
			print "Error : ", output
			continue

		parser = xml.sax.make_parser()
		parser.setFeature(xml.sax.handler.feature_namespaces, 0)
		Handler = endpointHandler(osInfo)
		parser.setContentHandler(Handler)
		parser.parse('osDiscovery.xml')

		for info in osInfo.keys():
			print osInfo[info]
			if 'os' not in osInfo[info]:
				continue
			if 'windows' not in osInfo[info]['os'].lower():
				continue

			hostip = osInfo[info]['ipAddr']
			devicetype = osInfo[info]['os']
			if devicetype in osMap.keys():
				devicetype = osMap[devicetype]
			macaddress = osInfo[info]['macAddr']
			vendor = osInfo[info]['vendor']
			domain = osInfo[info]['domain']
			status = osInfo[info]['status']

			db.save(hostip, devicetype, macaddress, vendor, domain, status)

if __name__ == "__main__":
	# osInfo = {}
	osDiscovery()
	# osMap = {
 #        "Windows XP (Windows 2000 LAN Manager)" : "Windows XP",
 #        "Windows 5.1" : "Windows XP",
 #        "Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)" : "Windows 7 Service Pack 1",
 #        "Windows 7 Professional 7601 Service Pack 1" : "Windows 7 Service Pack 1",
 #        "Windows 8.1 Pro 9600 (Windows 8.1 Pro 6.3)" : "Windows 8.1",
 #        "Windows 8.1 Pro 9600" : "Windows 8.1",
 #        "Windows 10 Enterprise 10240 (Windows 10 Enterprise 6.3)" : "Windows 10",
 #        "Windows 10 Enterprise 10240" : "Windows 10",
 #        "Windows 10 Pro 10586 (Windows 10 Pro 6.3)" : "Windows 10",
 #        "Windows 10 Pro 10586" : "Windows 10",
 #        "Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)" : "Windows Server 2012 R2",
 #        }

	# db = Database()

	# parser = xml.sax.make_parser()
	# parser.setFeature(xml.sax.handler.feature_namespaces, 0)
	# Handler = endpointHandler(osInfo)
	# parser.setContentHandler(Handler)
	# parser.parse('osDiscovery.xml')

	# for os in osInfo.keys():
	# 	print osInfo[os]
	# 	if 'os' not in osInfo[os]:
	# 		continue
	# 	if 'windows' not in osInfo[os]['os'].lower():
	# 		continue

	# 	hostip = osInfo[os]['ipAddr']
	# 	devicetype = osInfo[os]['os']
	# 	if devicetype in osMap.keys():
	# 		devicetype = osMap[devicetype]
	# 	macaddress = osInfo[os]['macAddr']
	# 	vendor = osInfo[os]['vendor']
	# 	domain = osInfo[os]['domain']
	# 	status = osInfo[os]['status']

	# 	db.save(hostip, devicetype, macaddress, vendor, domain, status)