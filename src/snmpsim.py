import yaml
import socket
import ipaddress
import csv
import json
from typing import Dict, List, Union
from pysnmp.hlapi import *
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto.api import v2c
from pysnmp.smi import builder, instrum, exval
import asyncio
import random
from datetime import datetime

class ConfigLoader:
    @staticmethod
    def load_config(config_file: str) -> dict:
        """Load YAML configuration file"""
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)

    @staticmethod
    def load_csv_data(csv_file: str) -> List[dict]:
        """Load CSV data file"""
        data = []
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                data.append(row)
        return data

class ResponseGenerator:
    def __init__(self, csv_data: List[dict]):
        self.csv_data = csv_data
        self.mac_counters = {}  # Track MAC address counters per prefix

    def parse_range(self, value: str) -> List[str]:
        """Parse range values in format 'start-end' or semicolon-separated values"""
        if not value or not isinstance(value, str):
            return [value]

        if ';' in value:
            return value.split(';')
        elif '-' in value and '$$' not in value:
            start, end = value.split('-')
            return [str(i) for i in range(int(start), int(end) + 1)]
        return [value]

    def generate_mac(self, prefix: str) -> str:
        """Generate MAC address with given prefix"""
        if prefix not in self.mac_counters:
            self.mac_counters[prefix] = 0

        counter = self.mac_counters[prefix]
        self.mac_counters[prefix] += 1

        # Convert counter to MAC suffix
        suffix = format(counter, '06x')
        return f"{prefix}{suffix}"

    def get_response_value(self, field: str, ip: str) -> str:
        """Get response value for a field, handling ranges and dynamic values"""
        for entry in self.csv_data:
            if self.ip_in_range(ip, entry['iprange']):
                value = entry[field]
                if '$$' in value:  # Dynamic MAC address
                    prefix = value.split('$$')[0]
                    return self.generate_mac(prefix)
                else:
                    possible_values = self.parse_range(value)
                    return random.choice(possible_values)
        return ''

    @staticmethod
    def ip_in_range(ip: str, ip_range: str) -> bool:
        """Check if IP is in the specified range"""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range)
        except ValueError:
            return False

class SNMPAgent:
    def __init__(self, config_file: str, csv_file: str):
        self.config = ConfigLoader.load_config(config_file)
        self.csv_data = ConfigLoader.load_csv_data(csv_file)
        self.response_generator = ResponseGenerator(self.csv_data)
        self.engine = engine.SnmpEngine()
        self.context = context.SnmpContext(self.engine)

        # Set up MIB
        self.setup_mib()

        # Configure SNMP versions
        self.setup_snmp_versions()

    def setup_mib(self):
        """Set up MIB with required OIDs"""
        mib_builder = builder.MibBuilder()

        # Define OID to field mapping
        self.oid_mapping = {
            '1.3.6.1.2.1.1.1': 'sysDesc',
            '1.3.6.1.2.1.1.2': 'sysObjectID',
            '1.3.6.1.2.1.1.4': 'sysContact',
            '1.3.6.1.2.1.1.5': 'sysName',
            '1.3.6.1.2.1.1.6': 'sysLocation',
            '1.3.6.1.2.1.25.3.2.1.3': 'hrDeviceType',
            '1.3.6.1.2.1.25.3.2.1.4': 'hrDeviceDescr',
            '1.3.6.1.2.1.47.1.1.1.1.2': 'entPhysicalDescr',
            '1.3.6.1.2.1.47.1.1.1.1.7': 'entPhysicalName',
            '1.3.6.1.2.1.47.1.1.1.1.8': 'entPhysicalHardwareRev',
            '1.3.6.1.2.1.47.1.1.1.1.9': 'entPhysicalFirmwareRev',
            '1.3.6.1.2.1.47.1.1.1.1.10': 'entPhysicalSoftwareRev',
            '1.3.6.1.2.1.47.1.1.1.1.11': 'entPhysicalSerialNum',
            '1.3.6.1.2.1.47.1.1.1.1.12': 'entPhyiscalMfgName',
            '1.3.6.1.2.1.47.1.1.1.1.13': 'entPhyiscalModelName',
        }

    def setup_snmp_versions(self):
        """Configure SNMP version-specific settings"""
        # SNMPv1/v2c community
        config.addV1System(self.engine, 'read-comm', self.config['snmp']['community'])

        # SNMPv3 settings
        if 'v3' in self.config['snmp']:
            config.addV3User(
                self.engine,
                self.config['snmp']['v3']['username'],
                config.usmHMACMD5AuthProtocol,
                self.config['snmp']['v3']['auth_key'],
                config.usmDESPrivProtocol,
                self.config['snmp']['v3']['priv_key']
            )

    async def handle_get_request(self, request):
        """Handle SNMP GET requests"""
        oid = str(request['name'])
        client_ip = request['transport_address'][0]

        if oid in self.oid_mapping:
            field = self.oid_mapping[oid]
            value = self.response_generator.get_response_value(field, client_ip)
            return v2c.OctetString(value)

        return v2c.NoSuchInstance()

    async def start(self):
        """Start SNMP agent"""
        for ip_range in self.config['listen']['ip_ranges']:
            transport = udp.UdpTransport()
            await transport.openServerMode((ip_range['ip'], self.config['listen']['port']))

            # Create response handler
            cmdrsp.GetCommandResponder(self.context)
            cmdrsp.NextCommandResponder(self.context)
            cmdrsp.BulkCommandResponder(self.context)

        print(f"SNMP agent started on port {self.config['listen']['port']}")

        while True:
            await asyncio.sleep(1)

def main():
    # Load configuration and start agent
    agent = SNMPAgent('data/config.yaml', 'data/data.csv')

    loop = asyncio.get_event_loop()
    loop.create_task(agent.start())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nShutting down SNMP agent...")
        loop.close()

if __name__ == "__main__":
    main()