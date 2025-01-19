    import socket
    import struct
    import yaml
    import ipaddress
    import csv
    import json
    from typing import Dict, List, Union
    import asyncio
    from datetime import datetime
    import binascii

    class SNMPPacket:
        def __init__(self):
            self.version = None
            self.community = None
            self.pdu_type = None
            self.request_id = None
            self.error_status = 0
            self.error_index = 0
            self.varbinds = []

        @staticmethod
        def decode_length(data: bytes, offset: int) -> tuple:
            """Decode ASN.1 length field"""
            if data[offset] < 128:
                return data[offset], offset + 1

            length_octets = data[offset] & 0x7F
            length = 0
            offset += 1
            for _ in range(length_octets):
                length = (length << 8) | data[offset]
                offset += 1
            return length, offset

        @staticmethod
        def encode_length(length: int) -> bytes:
            """Encode ASN.1 length field"""
            if length < 128:
                return bytes([length])

            length_bytes = []
            temp_length = length
            while temp_length:
                length_bytes.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            return bytes([0x80 | len(length_bytes)] + length_bytes)

        def decode(self, data: bytes) -> None:
            """Decode SNMP packet"""
            offset = 0
            # Sequence
            if data[offset] != 0x30:
                raise ValueError("Invalid SNMP packet")
            length, offset = self.decode_length(data, offset + 1)

            # Version
            if data[offset] != 0x02:
                raise ValueError("Invalid version field")
            ver_len, offset = self.decode_length(data, offset + 1)
            self.version = int.from_bytes(data[offset:offset + ver_len], 'big')
            offset += ver_len

            # Community
            if data[offset] != 0x04:
                raise ValueError("Invalid community field")
            comm_len, offset = self.decode_length(data, offset + 1)
            self.community = data[offset:offset + comm_len].decode()
            offset += comm_len

            # PDU
            self.pdu_type = data[offset]
            pdu_len, offset = self.decode_length(data, offset + 1)

            # Request ID
            if data[offset] != 0x02:
                raise ValueError("Invalid request ID field")
            req_len, offset = self.decode_length(data, offset + 1)
            self.request_id = int.from_bytes(data[offset:offset + req_len], 'big')
            offset += req_len

            # Parse varbinds
            while offset < len(data):
                if data[offset] == 0x30:  # Sequence
                    seq_len, offset = self.decode_length(data, offset + 1)
                    # Parse OID and value
                    oid_type = data[offset]
                    oid_len, offset = self.decode_length(data, offset + 1)
                    oid = self.decode_oid(data[offset:offset + oid_len])
                    offset += oid_len

                    value_type = data[offset]
                    value_len, offset = self.decode_length(data, offset + 1)
                    value = data[offset:offset + value_len]
                    offset += value_len

                    self.varbinds.append((oid, value_type, value))

        @staticmethod
        def decode_oid(data: bytes) -> str:
            """Decode ASN.1 OID"""
            oid = []
            first_byte = data[0]
            oid.extend([first_byte // 40, first_byte % 40])

            value = 0
            for byte in data[1:]:
                if byte & 0x80:
                    value = (value << 7) | (byte & 0x7F)
                else:
                    value = (value << 7) | byte
                    oid.append(value)
                    value = 0
            return '.'.join(map(str, oid))

    class RawSNMPAgent:
        def __init__(self, config_file: str, csv_file: str):
            self.config = self.load_config(config_file)
            self.csv_data = self.load_csv_data(csv_file)
            self.sockets = {}
            self.running = False

        @staticmethod
        def load_config(config_file: str) -> dict:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)

        @staticmethod
        def load_csv_data(csv_file: str) -> List[dict]:
            data = []
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    data.append(row)
            return data

        def create_raw_socket(self, ip_range: str) -> socket.socket:
            """Create a raw socket for SNMP"""
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.bind((ip_range, 0))
            return sock

        def generate_response(self, request: SNMPPacket, client_address: tuple) -> bytes:
            """Generate SNMP response"""
            # Implementation of response generation based on CSV data
            response = bytearray()
            # Add SNMP response header
            response.extend([0x30])  # Sequence

            # Version
            response.extend([0x02, 0x01, request.version])

            # Community
            community_bytes = request.community.encode()
            response.extend([0x04, len(community_bytes)])
            response.extend(community_bytes)

            # Response PDU
            response.extend([0xA2])  # Response PDU type

            # Request ID
            req_id_bytes = request.request_id.to_bytes((request.request_id.bit_length() + 7) // 8, 'big')
            response.extend([0x02, len(req_id_bytes)])
            response.extend(req_id_bytes)

            # Error status and index
            response.extend([0x02, 0x01, 0x00])  # Error status
            response.extend([0x02, 0x01, 0x00])  # Error index

            # Varbinds
            varbind_section = bytearray()
            for oid, _, _ in request.varbinds:
                # Get value from CSV data
                value = self.get_value_from_csv(oid, client_address[0])
                varbind = self.encode_varbind(oid, value)
                varbind_section.extend(varbind)

            response.extend([0x30, len(varbind_section)])
            response.extend(varbind_section)

            # Update total length
            total_length = len(response) - 2
            length_bytes = SNMPPacket.encode_length(total_length)
            response[1:1] = length_bytes

            return bytes(response)

        def encode_varbind(self, oid: str, value: str) -> bytes:
            """Encode a varbind for SNMP response"""
            varbind = bytearray()
            varbind.extend([0x30])  # Sequence

            # OID
            oid_bytes = self.encode_oid(oid)
            varbind.extend([0x06, len(oid_bytes)])
            varbind.extend(oid_bytes)

            # Value
            value_bytes = value.encode()
            varbind.extend([0x04, len(value_bytes)])
            varbind.extend(value_bytes)

            # Update length
            total_length = len(varbind) - 2
            length_bytes = SNMPPacket.encode_length(total_length)
            varbind[1:1] = length_bytes

            return bytes(varbind)

        @staticmethod
        def encode_oid(oid: str) -> bytes:
            """Encode OID in ASN.1 format"""
            numbers = [int(x) for x in oid.split('.')]
            result = bytearray([numbers[0] * 40 + numbers[1]])

            for number in numbers[2:]:
                if number < 128:
                    result.append(number)
                else:
                    bytes_needed = (number.bit_length() + 6) // 7
                    for i in range(bytes_needed - 1, -1, -1):
                        byte = (number >> (i * 7)) & 0x7F
                        if i != 0:
                            byte |= 0x80
                        result.append(byte)

            return bytes(result)

        async def handle_packet(self, sock: socket.socket):
            """Handle incoming SNMP packets"""
            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    # Skip IP header (20 bytes) and UDP header (8 bytes)
                    snmp_data = data[28:]

                    # Parse SNMP packet
                    packet = SNMPPacket()
                    packet.decode(snmp_data)

                    # Generate response
                    response = self.generate_response(packet, addr)

                    # Create UDP header
                    udp_length = len(response) + 8
                    udp_header = struct.pack('!HHHH',
                        161,                    # Source port
                        addr[1],                # Destination port
                        udp_length,             # Length
                        0)                      # Checksum (zero for now)

                    # Create IP header
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                        0x45,                   # Version and IHL
                        0,                      # Type of Service
                        20 + udp_length,        # Total Length
                        0,                      # ID
                        0,                      # Flags and Fragment Offset
                        255,                    # TTL
                        socket.IPPROTO_UDP,     # Protocol
                        0,                      # Checksum (zero for now)
                        socket.inet_aton(sock.getsockname()[0]),  # Source IP
                        socket.inet_aton(addr[0]))                # Destination IP

                    # Calculate checksums
                    ip_checksum = self.calculate_checksum(ip_header)
                    ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]

                    pseudo_header = struct.pack('!4s4sBBH',
                        socket.inet_aton(sock.getsockname()[0]),
                        socket.inet_aton(addr[0]),
                        0,
                        socket.IPPROTO_UDP,
                        udp_length)
                    udp_checksum = self.calculate_checksum(pseudo_header + udp_header + response)
                    udp_header = udp_header[:6] + struct.pack('!H', udp_checksum)

                    # Send response
                    sock.sendto(ip_header + udp_header + response, addr)

                except Exception as e:
                    print(f"Error handling packet: {e}")
                    continue

        @staticmethod
        def calculate_checksum(data: bytes) -> int:
            """Calculate IP/UDP checksum"""
            if len(data) % 2 == 1:
                data += b'\0'
            words = struct.unpack('!%dH' % (len(data) // 2), data)
            checksum = sum(words)
            checksum = (checksum >> 16) + (checksum & 0xFFFF)
            checksum += checksum >> 16
            return ~checksum & 0xFFFF

        async def start(self):
            """Start the SNMP agent"""
            self.running = True

            for ip_range in self.config['listen']['ip_ranges']:
                sock = self.create_raw_socket(ip_range['ip'])
                self.sockets[ip_range['ip']] = sock
                asyncio.create_task(self.handle_packet(sock))

            print("SNMP agent started with raw sockets")

            while self.running:
                await asyncio.sleep(1)

        def stop(self):
            """Stop the SNMP agent"""
            self.running = False
            for sock in self.sockets.values():
                sock.close()

    if __name__ == "__main__":
        agent = RawSNMPAgent('config.yaml', 'data.csv')

        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(agent.start())
        except KeyboardInterrupt:
            print("\nShutting down SNMP agent...")
            agent.stop()
            loop.close()