# Packet Sniffer 

## About
The project is a program to get access to the data flowing through your router/ethernet. Any kind of data can be sniffed from the network.

## Functioning
The file sniffer.py  when run using Python 3 will listen to packets received from the socket connection. On receiving the Ethernet frame, the program will break it into individual pieces to ascertain the kind of Protocols. i.e IPv4/IPv6 and ICMP,TCP,UDP (ICMP: Internet Control Message Protocol, TCP: Transmission Control Protocol (Most Common), UDP: User Datagram Protocol). Each protocol incorporates discrete byte information. So the method to unpack the data is distinct. 

## Usefulness
It is useful for finding out the bottlenecks in the network

## Requirements 
Needs Super-User permission for certain utilities to function.
