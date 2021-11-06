# Packet Sniffer 

## About
The project is a program to get access to the data flowing through your router/ethernet. Any kind of data can be sniffed from the network.

## Functioning
The file sniffer.py  when run using Python 3 will listen to packets received from the socket connection. On receiving the Ethernet frame, the program will break it into individual pieces to ascertain the kind of Protocols. i.e IPv4/IPv6 and ICMP,TCP,UDP (ICMP: Internet Control Message Protocol, TCP: Transmission Control Protocol (Most Common), UDP: User Datagram Protocol). Each protocol incorporates discrete byte information. So the method to unpack the data is distinct. 

 1. Socket object is created
 2. Bind socket to IP address and port
 3. Server can now listen/wait for connections
 4. Clients will attempt to connect, server can then accept connections

Once connection is made, server and client enter request/response (send/receive) loop. When connection is closed, server returns to listening state

## Usefulness
It is useful for finding out the bottlenecks in the network

## Requirements 
Needs Super-User permission for certain utilities to function.

## Resources

1. http://www.binarytides.com/python-packet-sniffer-code-linux/

2. https://docs.python.org/3.4/library/struct.html#format-characters

