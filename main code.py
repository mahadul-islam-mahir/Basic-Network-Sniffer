import socket
import struct
import textwrap



#Unpack Ethernet Frame
def ethernet_frame(data):
    destination_add, src_add, prot_typ = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_add(destination_add), get_mac_add(src_add), prot_typ, data[14:]

# formatting MAC address
def get_mac_add(bytes_add):
    bytes_str = map('{:02x}'.format, bytes_add)
    return ':'.join(bytes_str).upper()

# Unpack IPv4
def IPv4_packet(data):
    version_header_lngth = data[0]
    version = version_header_lngth >> 4
    header_lngth = (version_header_lngth & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_lngth, ttl, protocol, IPv4(src), IPv4(target), data[header_lngth:]

#Formatting IPv4
def IPv4(add):
    return '.'.join(map(str, add))

#Unpack ICMP
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpack TCP
def tcp_packet(data):
    src_port, destination_port, sequence, acknowledgement, offset_reserve_flag = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserve_flag >> 12) * 4
    flag_urg = (offset_reserve_flag & 32) >> 5
    flag_ack = (offset_reserve_flag & 16) >> 4
    flag_psh = (offset_reserve_flag & 8) >> 3
    flag_rst = (offset_reserve_flag & 4) >> 2
    flag_syn = (offset_reserve_flag & 2) >> 1
    flag_fin = offset_reserve_flag & 1
    return src_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpack UDP
def udp_packet(data):
    src_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, destination_port, size, data[8:]

#Format Multi-Line Data
def format_multiline(prefix, string, size=80):
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    size -= len(prefix)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, add = connection.recvfrom(65536)
        destination_add, src_add, prot_typ, data = ethernet_frame(raw_data)
        print('\nEthernet Frame :')
        print('Destination : {}, Source : {}, Protocol Type : {}'.format(destination_add, src_add, hex(prot_typ)))

        if prot_typ == 0x0800:
            version, header_lngth, ttl, protocol, src, target, data = IPv4_packet(data)
            print('Ipv4 Packet:')
            print('Version: {}, Header: {}, TTL: {}'.format(version,header_lngth,ttl))
            print('Protocol: {}, Source: {}, Target: {}'.format(protocol,src,target))

            if protocol == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('ICMP Packet:')
                print('Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print('Data:')
                print(format_multiline('', data))
            elif protocol == 6:
                src_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet(data)
                print('TCP Packet:')
                print('Source: {}, Destination: {}, Sequence: {}'.format(src_port, destination_port, sequence))
                print('Acknowledgement: {}, Flag_URG: {}, Flag_ACK: {}'.format(acknowledgement, flag_urg, flag_ack))
                print('Flag_PSH: {}, Flag_RST: {}, Flag_SYN: {}, Flag_FIN: {}'.format(flag_psh, flag_rst, flag_syn, flag_fin))
                print('Data:')
                print(format_multiline('', data))
            elif protocol == 17:
                src_port, destination_port, size, data = udp_packet(data)
                print('UDP Packet:')
                print('Source: {}, Destinatin: {}, Size: {}'.format(src_port, destination_port, size))
                print('Data:')
                print(format_multiline('', data))
            else:
                print('Unknown Protocol Data:')
                print(format_multiline('', data))
        else:
            print('Non-IPv4 Protocol Data:')
            print(format_multiline('', data))


if __name__ == "__main__":
    main()