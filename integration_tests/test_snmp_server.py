# integration_tests/test_snmp_server.py
import socket
import struct
import time
import sys

def create_snmp_get_request(community: str, oid: str) -> bytes:
    # Create a simple SNMP GET request
    oid_bytes = bytes([int(x) for x in oid.split('.')])

    # Build SNMP packet
    snmp_packet = (
        b'\x30\x26'  # Sequence
        b'\x02\x01\x00'  # Version: v1 (0)
        + struct.pack('!BB', 0x04, len(community)) + community.encode()  # Community
        b'\xa0\x19'  # GetRequest PDU
        b'\x02\x01\x01'  # Request ID: 1
        b'\x02\x01\x00'  # Error Status: 0
        b'\x02\x01\x00'  # Error Index: 0
        b'\x30\x0e'  # Varbind list
        b'\x30\x0c'  # Varbind
        + struct.pack('!BB', 0x06, len(oid_bytes)) + oid_bytes  # OID
        b'\x05\x00'  # NULL
    )

    return snmp_packet

def test_snmp_server():
    # Create raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        # Create SNMP GET request
        snmp_request = create_snmp_get_request('public', '1.3.6.1.2.1.1.1.0')

        # Create UDP header
        udp_header = struct.pack('!HHHH',
            49152,      # Source port
            161,        # Destination port
            len(snmp_request) + 8,  # UDP length
            0)         # Checksum (to be filled in)

        # Create IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45,       # Version and IHL
            0,          # Type of Service
            20 + 8 + len(snmp_request),  # Total Length
            0,          # ID
            0,          # Flags and Fragment Offset
            255,        # TTL
            socket.IPPROTO_UDP,  # Protocol
            0,          # Checksum (to be filled in)
            socket.inet_aton('127.0.0.1'),  # Source IP
            socket.inet_aton('127.0.0.1'))  # Destination IP

        # Send packet
        packet = ip_header + udp_header + snmp_request
        sock.sendto(packet, ('127.0.0.1', 0))

        # Receive response
        response, addr = sock.recvfrom(65535)

        # Skip IP and UDP headers
        snmp_response = response[28:]

        # Basic validation
        assert len(snmp_response) > 0
        assert snmp_response[0] == 0x30  # SNMP sequence
        print("SNMP server test passed!")
        sys.exit(0)

    except Exception as e:
        print(f"Test failed: {e}")
        sys.exit(1)

    finally:
        sock.close()

if __name__ == '__main__':
    test_snmp_server()