#!/usr/bin/env python3
import os
import sys
import json
import requests
import ipaddress
import re

# API Key - IMPORTANT: Replace with your actual AlienVault OTX API key
API_KEY = 'OTX-API-KEY'
OTX_SERVER = 'https://otx.alienvault.com'

def validate_input(input_str):
    """
    Validate and determine the type of input
    :param input_str: Input string to validate
    :return: Tuple of (type, validated input)
    """
    # Check if it's an IP address
    try:
        # Validate both IPv4 and IPv6
        ip = ipaddress.ip_address(input_str)
        return 'ip', str(ip)
    except ValueError:
        pass

    # Check if it's a domain
    domain_regex = r'^(?!-)[A-Za-z0-9-]+([-.][A-Za-z0-9-]+)*\.[A-Z|a-z]{2,}$'
    if re.match(domain_regex, input_str):
        return 'domain', input_str

    # Check if it's a hash (MD5, SHA1, SHA256)
    hash_patterns = {
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$'
    }

    for hash_type, pattern in hash_patterns.items():
        if re.match(pattern, input_str):
            return hash_type, input_str

    return None, None

def check_reputation(input_str):
    """
    Check reputation of input using AlienVault OTX
    :param input_str: Input to check (hash, IP, or domain)
    :return: List of alerts or None
    """
    try:
        # Validate input
        input_type, validated_input = validate_input(input_str)
        if not input_type:
            return None

        # Construct appropriate API URL based on input type
        if input_type == 'ip':
            url = f'{OTX_SERVER}/api/v1/indicators/ip/{validated_input}/general'
        elif input_type == 'domain':
            url = f'{OTX_SERVER}/api/v1/indicators/domain/{validated_input}/general'
        elif input_type in ['md5', 'sha1', 'sha256']:
            url = f'{OTX_SERVER}/api/v1/indicators/file/{validated_input}/general'
        else:
            return None

        # Prepare API request
        headers = {
            'X-OTX-API-KEY': API_KEY,
            'User-Agent': 'OTX Python API'
        }

        response = requests.get(url, headers=headers)

        # Check if request was successful
        if response.status_code == 200:
            data = response.json()

            # Check pulse information
            pulse_info = data.get('pulse_info', {})
            if pulse_info.get('count', 0) > 0:
                alerts = []
                for pulse in pulse_info.get('pulses', []):
                    alerts.append({
                        'name': pulse.get('name', 'Unknown Pulse'),
                        'description': pulse.get('description', 'No description')
                    })
                return alerts

        return None
    except Exception as e:
        print(f"Error checking {input_str}: {e}", file=sys.stderr)
        return None

def send_event(msg, agent=None):
    """
    Send event to Wazuh socket
    :param msg: Message to send
    :param agent: Agent information
    """
    try:
        from socket import socket, AF_UNIX, SOCK_DGRAM

        # Get the current working directory
        pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

        # Define the Unix socket address for sending events
        socket_addr = f'{pwd}/queue/sockets/queue'

        # Prepare the socket message
        if not agent or agent.get("id") == "000":
            string = f'1:alienvault_stats:{json.dumps(msg)}'
        else:
            string = f'1:[{agent.get("id")}] ({agent.get("name")}) {agent.get("ip", "any")}->alienvault_stats:{json.dumps(msg)}'

        # Send the event via Unix socket
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        print(f"Error sending event: {e}", file=sys.stderr)

def process_alert(alert_file_path):
    """
    Process a single alert file
    :param alert_file_path: Path to the alert JSON file
    """
    try:
        # Read the entire file content
        with open(alert_file_path, 'r') as alert_file:
            file_content = alert_file.read()

        # Try to parse JSON, handling potential multi-line or multiple JSON objects
        # Split the content by newlines and try to parse each line
        alerts = []
        for line in file_content.split('\n'):
            line = line.strip()
            if line:
                try:
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    # If a single line fails, try parsing the whole content
                    try:
                        alerts = json.loads(file_content)
                        break
                    except json.JSONDecodeError:
                        print(f"Could not parse JSON: {line}", file=sys.stderr)

        # Process each alert
        for alert in alerts:
            # Extract relevant information
            input_values = []

            # Extract from different possible locations
            if 'data' in alert:
                # Check for Windows event data (DNS query)
                if 'win' in alert['data'] and 'eventdata' in alert['data']['win']:
                    query_name = alert['data']['win']['eventdata'].get('queryName')
                    if query_name:
                        input_values.append(query_name)

                # Check for other possible locations
                if 'srcip' in alert['data']:
                    input_values.append(alert['data']['srcip'])
                if 'dstip' in alert['data']:
                    input_values.append(alert['data']['dstip'])

            # Process each potential input value
            for input_value in input_values:
                # Check reputation
                alerts = check_reputation(input_value)

                if alerts:
                    # Prepare alert output
                    alert_output = {
                        "integration": "alienvault",
                        "alienvault_alert": {
                            "query": input_value,
                            "threats": alerts
                        }
                    }

                    # Send event to Wazuh
                    send_event(alert_output, alert.get('agent', {}))

                    # Print information
                    print(f"Potential threat found for {input_value}:")
                    for threat in alerts:
                        print(f"  - Name: {threat.get('name', 'Unknown')}")
                        print(f"  - Description: {threat.get('description', 'No description')}")

    except Exception as e:
        print(f"Error processing alert file: {e}", file=sys.stderr)

def main():
    # Check if file path is provided
    if len(sys.argv) < 2:
        print("Usage: custom-alienvault.py <alert_file_path>", file=sys.stderr)
        sys.exit(1)

    # Process the alert file
    process_alert(sys.argv[1])

if __name__ == '__main__':
    main()
