# PortScanner
Author: Tanis Reed

Usage: ./portScanner.py -h [hosts] -p [ports] optional-->[-u] 

*Hosts and ports are required, and -u option will tell the scanner to do a UDP scan as well as a TCP Syn scan.
*Hosts can be a comma-separated list of hosts, or a text file containing a list of hosts.
*Ports must (at the moment) be a comma-separated list of ports

Command-line output is not terribly coherent, but the scanenr will output a PDF report for the user, within the same directory as this scanner.

FEATURES:
  IP/ICMP Ping to check host responsiveness (Will not scan hosts that do not respond to this ping!)
  Traceroute using UDP
  TCP/UDP scanning
  Multiple hosts and ports (hosts are command-line comma-separated lists or from text file. Ports are comma-separated lists on command line)
  PDF report generation
  Multithreading (Spawns one thread per port) for higher efficiency and speed
  
  
