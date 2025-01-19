# tests/test_snmp_server.py
import pytest
import socket
import asyncio
from snmp_server import RawSNMPAgent, SNMPPacket

@pytest.fixture
async def snmp_agent():
    agent = RawSNMPAgent('config.yaml', 'data.csv')
    yield agent
    agent.stop()

@pytest.mark.asyncio
async def test_agent_initialization(snmp_agent):
    assert snmp_agent.config is not None
    assert snmp_agent.csv_data is not None

@pytest.mark.asyncio
async def test_packet_decoding():
    # Sample SNMP GET request packet
    sample_packet = bytes.fromhex(
        '30'    # Sequence
        '26'    # Length
        '02 01 00'  # Version: v1 (0)
        '04 06 70 75 62 6c 69 63'  # Community: "public"
        'a0 19'  # GetRequest PDU
        '02 01 01'  # Request ID: 1
        '02 01 00'  # Error Status: 0
        '02 01 00'  # Error Index: 0
        '30 0e'  # Varbind list
        '30 0c'  # Varbind
        '06 08 2b 06 01 02 01 01 01 00'  # OID: .1.3.6.1.2.1.1.1.0
        '05 00'  # NULL
    )

    packet = SNMPPacket()
    packet.decode(sample_packet)

    assert packet.version == 0
    assert packet.community == 'public'
    assert packet.request_id == 1
    assert len(packet.varbinds) == 1

@pytest.mark.asyncio
async def test_response_generation(snmp_agent):
    sample_request = SNMPPacket()
    sample_request.version = 0
    sample_request.community = 'public'
    sample_request.request_id = 1
    sample_request.varbinds = [('.1.3.6.1.2.1.1.1.0', 0x05, b'')]

    response = snmp_agent.generate_response(sample_request, ('192.168.1.1', 161))
    assert response is not None
    assert len(response) > 0

@pytest.mark.asyncio
async def test_socket_creation(snmp_agent):
    sock = snmp_agent.create_raw_socket('127.0.0.1')
    assert sock is not None
    assert sock.family == socket.AF_INET
    assert sock.type == socket.SOCK_RAW
    sock.close()