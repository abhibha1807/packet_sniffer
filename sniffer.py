import socket
import textwrap
import struct


# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

class Ethernet:

    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]


class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        flags = raw_data[6] & 224
        print("raw flag data" + str(raw_data[6]))
        self.flag_1 = 0
        self.flag_2 = 0
        self.flag_3 = 0
        if(flags == 1 or flags == 3):
        	self.flag_3 = 1
        elif(flags == 3 or flags == 2):
        	self.flag_2 = 1

        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    # Returns properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))


class TCP:

    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]



class UDP:

    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]




def main():
	# The ntohs() function converts the unsigned short integer netshort from network byte order to host byte order.

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(12000)
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print("\t - " + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print("\t - " + 'IPv4 Packet:')
            # print("\t\t - " + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print("\t\t - "+ 'Flag 1 :{}, Flag 2 :{}, Flag 3 :{}'.format(ipv4.flag_1, ipv4.flag_2, ipv4.flag_3))
            # print("\t\t - " + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
            TCP
            if ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print("\t - " + 'TCP Segment:')
                print("\t\t - " + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print("\t\t - " + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print("\t\t - " + 'Flags:')
                print("\t\t\t - " + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print("\t\t\t - " + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                print("\t\t - " + 'TCP Data:')
                print(format_multi_line("\t\t\t  ", tcp.data))

            # UDP
            # elif ipv4.proto == 17:
            #     udp = UDP(ipv4.data)
            #     print("\t - " + 'UDP Segment:')
            #     print("\t\t - " + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # # Other IPv4
            # else:
            #     print("\t - " + 'Other IPv4 Data:')
            #     print(format_multi_line("\t\t  ", ipv4.data))

        # else:
        #     print('Ethernet Data:')
        #     print(format_multi_line("\t   ", eth.data))



main()
