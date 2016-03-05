#! /usr/bin/env python

#Python Scapy tool for port scanning...
#Author: Tanis Reed

from scapy.all import *
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, inch, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import *
import sys, getopt
import threading

#Global variable for convenience
hostList = []

#Small "host" class to store my information to later be printed into a PDF report.
class HOST:
	
	def __init__(self, address, route):
		self.address = address;
		self.traceroute = route;
		self.ports = []
		self.protocols = []
		self.port_stati = []

	def addPort(self, port, protocol, status):
		self.ports.append(str(port))
		self.protocols.append(protocol)
		self.port_stati.append(status)

#Threading class to help speed up large scans
class portThread(threading.Thread):
	#Overwrite Init function:
	def __init__(self, host, port, upd_selected):
		threading.Thread.__init__(self)
		self.lock = threading.Lock()
		self.host = host;
		self.port = port;
		self.udp = upd_selected;
	
	#Function for tcp scanning
	def do_tcp_scans(host,port):
		print "\n"	
		ip = IP(dst = host)
		src_port = RandShort()	
		tcp_scan = sr1(ip/TCP(dport=port,sport = src_port,flags = "S"), timeout = 1)
		if(str(type(tcp_scan))=="<type 'NoneType'>"):
			print "Filtered"
			return (port, "TCP", "Filtered")
		
		elif (tcp_scan.haslayer(TCP)):
			if (tcp_scan.getlayer(TCP).flags == 0x12):
				#Reset the connection
				sr(ip/TCP(dport=port,sport = src_port,flags = "S"), timeout = 1)
				printf("TCP: Port %s is open.\n", port);			
				return (port, "TCP", "Open")			
			
			elif (tcp_scan.getlayer(TCP).flags == 0x14): #With large scans we will ignore this part...
				#Closed port
				printf("TCP: Port %s is closed.\n", port);
				return (port, "TCP", "Closed")
	
	#Function for udp scanning
	def do_udp_scans(host, port):
		ip = IP(dst = host)
		print "\n"
		for count in range (0,3):	#Send 3 packets since it's UDP and more unreliable.
			udp_scan = sr1(ip/UDP(dport=port), timeout = 1)
			if(str(type(udp_scan)) == "<type 'NoneType'>"):
				printf('UDP: host %s has port %s open|filtered.\n', host, port);
				return (port, "UDP", "Open|Filtered")
			elif(udp_scan.haslayer(UDP)):
				printf('UDP: host %s has port %s open.\n', host, port);
				return (port, "UDP", "Open")
			elif(udp_scan.haslayer(ICMP)): #Get the ICMP code!
				if(int(udp_scan.getlayer(ICMP).type)==3 and int(udp_scan.getlayer(ICMP).code)==3):
					printf('UDP: host %s has port %s closed.\n', host, port);
					return (port, "UDP", "Closed")
				if(int(udp_scan.getlayer(ICMP).type)==3 and int(udp_scan.getlayer(ICMP).code) in [1,2,9,10,13]):
					printf('UDP: host %s has port %s filtered.\n', host, port);
					return (port, "UDP", "Filtered")
	
	#Entry point for the thread.
	def run(self):
		host = self.host;
		port = self.port;
		udpSelected = self.udp;
		if(do_ping(host)):
			printf("Host %s is alive!\n", host);
			hostObj = HOST(host, do_traceroute(host))
			
			a,b,c = do_tcp_scans(host, int(port));	#Tuple unpacking... Look at functions for variable names...
			if c != "Closed":				
				hostObj.addPort(a,b,c)
			if(udpSelected):
				a,b,c = do_udp_scans(host, int(port));
			if c != "Closed":				
				hostObj.addPort(a,b,c)
					
			#This is the SHARED resource! Do NOT corrupt!
			self.lock.acquire();
			hostList.append(hostObj);
			self.lock.release();

#Functions
#CreateReport function to create a PDF in the same folder that this scanner resides...
def createReport(hostList):
	#Populate a 2-D array based on the information from the Host objects to use in creating a table.
	data = [["IP Address", "Traceroute Result", "Ports Found", "Protocol", "Status"]]
	for host in hostList:
		if len(host.ports) > 0: #Make sure we found an open port and recorded information
			data.append([host.address, host.traceroute, host.ports[0], host.protocols[0], host.port_stati[0]]);
		else: 
			data.append([host.address, host.traceroute, "", "", ""])
		if len(host.ports) > 1: #append additional findings
			for i in range (1,len(host.ports)):
				data.append(["", "", host.ports[i], host.protocols[i], host.port_stati[i]]);
	print "\n\n"	
	print data
	print "\n\n"	
	
	#Some setup for page...
	name = raw_input("What would you like the PDF to be called? (Include the .pdf and be careful of overwrite!)")
	doc = SimpleDocTemplate(name, pagesize = A4, rightMargin = 30, leftMargin = 30, topMargin = 30, bottomMargin = 18);
	doc.pagesize = landscape(A4)
	elements = []

	#Configure the style... This style and doc code is mostly taken from ZEWAREN.net on how to write a table into a PDF using Python and ReportLab
	style = TableStyle([('ALIGN',(1,1),(-2,-2),'RIGHT'),
                       ('TEXTCOLOR',(1,1),(-2,-2),colors.red),
                       ('VALIGN',(0,0),(0,-1),'TOP'),
                       ('TEXTCOLOR',(0,0),(0,-1),colors.blue),
                       ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                       ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                       ('TEXTCOLOR',(0,-1),(-1,-1),colors.green),
                       ('INNERGRID', (0,0), (-1,-1), 0.25, colors.black),
                       ('BOX', (0,0), (-1,-1), 0.25, colors.black),
                       ])

	#Configure style and word wrap
	s = getSampleStyleSheet()
	s = s["BodyText"]
	s.wordWrap = 'CJK'
	data2 = [[Paragraph(cell, s) for cell in row] for row in data]
	t=Table(data2)
	t.setStyle(style)

	#Now we can build the file
	elements.append(t)
	doc.build(elements)

#Function for tcp scanning
def do_tcp_scans(host,port):
	print "\n"	
	ip = IP(dst = host)
	src_port = RandShort()	
	tcp_scan = sr1(ip/TCP(dport=port,sport = src_port,flags = "S"), timeout = 1)
	if(str(type(tcp_scan))=="<type 'NoneType'>"):
		print "Filtered"
		return (port, "TCP", "Filtered")
	
	elif (tcp_scan.haslayer(TCP)):
		if (tcp_scan.getlayer(TCP).flags == 0x12):
			#Reset the connection
			sr(ip/TCP(dport=port,sport = src_port,flags = "S"), timeout = 1)
			printf("TCP: Port %s is open.\n", port);			
			return (port, "TCP", "Open")			
		
		elif (tcp_scan.getlayer(TCP).flags == 0x14): #With large scans we will ignore this part...
			#Closed port
			printf("TCP: Port %s is closed.\n", port);
			return (port, "TCP", "Closed")
	
#Function for udp scanning
def do_udp_scans(host, port):
	ip = IP(dst = host)
	print "\n"
	for count in range (0,3):	#Send 3 packets since it's UDP and more unreliable.
		udp_scan = sr1(ip/UDP(dport=port), timeout = 1)
		if(str(type(udp_scan)) == "<type 'NoneType'>"):
			printf('UDP: host %s has port %s open|filtered.\n', host, port);
			return (port, "UDP", "Open|Filtered")
		elif(udp_scan.haslayer(UDP)):
			printf('UDP: host %s has port %s open.\n', host, port);
			return (port, "UDP", "Open")
		elif(udp_scan.haslayer(ICMP)): #Get the ICMP code!
			if(int(udp_scan.getlayer(ICMP).type)==3 and int(udp_scan.getlayer(ICMP).code)==3):
				printf('UDP: host %s has port %s closed.\n', host, port);
				return (port, "UDP", "Closed")
			if(int(udp_scan.getlayer(ICMP).type)==3 and int(udp_scan.getlayer(ICMP).code) in [1,2,9,10,13]):
				printf('UDP: host %s has port %s filtered.\n', host, port);
				return (port, "UDP", "Filtered")

#Simple printf for easy formatting
def printf(format, *args):
	sys.stdout.write(format % args)

#Ping method to test response of a box
def do_ping(host):
	ip = IP(dst = host)
	src_port = RandShort() #Random source port might look suspicious to IDS's... 
	ping = sr1(ip/ICMP(),timeout=1);
	return ping

#Usage function
def usage():
	print "Usage: ./portScanner.py -h <hosts> -p <ports> [other options]"
	sys.exit(2)

#User help function
def help():
	print "<hosts> can be a comma-separated list of hosts, or a text file containing a list of hosts"
	print "<ports> must be a comma-separated list of ports (Yes I know, not terribly useful... Was crunched for time!)"
	print "both <hosts> and <ports> must be specified."
	sys.exit(2)

#Function for traceroute
def do_traceroute(host):
	route = ""
	for i in range (1,4):
		tracer = IP(dst = host, ttl = i)/UDP(dport = 18723);
		response = sr1(tracer, timeout=1)
		if response is None:
			return route + " No traceroute information beyond this"
		if response.type == 3:	#we have found the target
			return route + str(response.src)
		route += str(response.src) + "," #Haven't found target yet, append this host...
		if i == 27: #Likely, something very weird went on or we're tracing something in the Middle East...
			return "No traceroute information..."
	
#Main Function
def main(argv):
	print "Welcome to Tanis's port scanner."
	if (len(argv) < 2):
		usage()
	try:
		opts, args = getopt.getopt(argv, "h:p:u", ["help"])
	except getopt.GetoptError:
		usage()
	found_h = False
	found_p = False
	#Handle command-line options
	for opt, arg in opts:
		#UDP? TCP by default...
		if opt == '-u':
			udpSelected = True
		#hosts!
		if opt == '-h':
			if arg.find(".txt") != -1:
				#print arg
				f = open(arg)
				hosts = []
				for line in f:
					#append to hosts
					hosts.append(line.strip('\n'))
			elif arg.find('/') != -1:
				#Subnet mask...
				index = arg.find('/')
				netmask = int(arg[index+1:])
				#print netmask
				hosts = []
				arg = arg[:index]
				#print arg
				pieces = arg.split('.')
				#print pieces
				newpieces = []
				for piece in pieces:
					piece = bin(int(piece)+256)[3:]
					newpieces.append(piece)
				binpieces = ''.join(newpieces)
				#print binpieces
				current = 0
				baseAddress = ""
				while current < netmask:
					baseAddress += (binpieces[current])
					current+=1
				#print baseAddress
				numFinalHosts = 2**(32 - netmask)
				#print "numfinalhosts: " + str(numFinalHosts)
				numAdded = 0
				while numAdded < numFinalHosts:
					extension = bin(numAdded + 2**32)[3+netmask:]
					newAddress = baseAddress + extension
					hostParts = ["","","",""]
					hostParts[0] = str(int(newAddress[0:8], 2))
					hostParts[1] = str(int(newAddress[8:16], 2))
					hostParts[2] = str(int(newAddress[16:24], 2))
					hostParts[3] = str(int(newAddress[24:32], 2))
					hosts.append('.'.join(hostParts))
					numAdded+=1
				#print hosts	
			else:
				hosts = arg.split(',')
			found_h = True
		#ports!
		elif opt == '-p':
			ports = arg.split(',')
			found_p = True
		#help!
		elif opt == '--help':
			help()
	if not found_h or not found_p:
		usage()	

	#Main lines for the scans...
	threads = []
	for host in hosts:
		if(do_ping(host)): #We've tested that it's alive and are ready to spawn a thread for every port we're hitting
			#printf("Host %s is alive!\n", host);
			#hostObj = HOST(host, do_traceroute(host))
			for port in ports:
				newThread = portThread(host, port, udpSelected)

				newThread.start()
				threads.append(newThread)
				#a,b,c = do_tcp_scans(host, int(port));	#Tuple unpacking... Look at functions for variable names...
				#if c != "Closed":				
				#	hostObj.addPort(a,b,c)
				#if(udpSelected):
				#	a,b,c = do_udp_scans(host, int(port));
				#if c != "Closed":				
				#	hostObj.addPort(a,b,c)
					
			#hostList.append(hostObj);

	#Wait for all of the threads to finish
	for t in threads:
		t.join()
	
	#Generate PDF Report:
	createReport(hostList)
	
if __name__ == "__main__":
	main(sys.argv[1:])
