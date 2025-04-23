#!/usr/bin/env python3
import os
import argparse
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

def check_ip_reputation(ip):
    """
    Check IP reputation using multiple AlienVault OTX API endpoints
    :param ip: IP address to check
    :return: List of alerts or None
    """
    try:
        # Prepare API request
        headers = {
            'X-OTX-API-KEY': API_KEY,
            'User-Agent': 'OTX Python API'
        }

        # Check general IP information
        general_url = f'{OTX_SERVER}/api/v1/indicators/ip/{ip}/general'
        general_response = requests.get(general_url, headers=headers)

        # Check reputation specifically
        reputation_url = f'{OTX_SERVER}/api/v1/indicators/ip/{ip}/reputation'
        reputation_response = requests.get(reputation_url, headers=headers)

        alerts = []

        # Process general information
        if general_response.status_code == 200:
            general_data = general_response.json()
            pulse_info = general_data.get('pulse_info', {})
            if pulse_info.get('count', 0) > 0:
                for pulse in pulse_info.get('pulses', []):
                    alerts.append({
                        'name': pulse.get('name', 'Unknown Pulse'),
                        'description': pulse.get('description', 'No description'),
                        'source': 'General Pulse'
                    })

        # Process reputation information
        if reputation_response.status_code == 200:
            reputation_data = reputation_response.json()

            # Check for specific reputation indicators
            reputation_str = reputation_data.get('reputation', '')
            if reputation_str:
                alerts.append({
                    'name': 'IP Reputation',
                    'description': f'Reputation: {reputation_str}',
                    'source': 'Reputation Check'
                })

        return alerts if alerts else None

    except Exception as e:
        print(f"Error checking IP {ip}: {e}")
        return None

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
            print(f"Invalid input: {input_str}")
            return None

        # Handle IP addresses separately
        if input_type == 'ip':
            return check_ip_reputation(validated_input)

        # Construct appropriate API URL based on input type
        if input_type == 'domain':
            url = f'{OTX_SERVER}/api/v1/indicators/domain/{validated_input}/general'
        elif input_type in ['md5', 'sha1', 'sha256']:
            url = f'{OTX_SERVER}/api/v1/indicators/file/{validated_input}/general'
        else:
            print(f"Unsupported input type: {input_type}")
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
        print(f"Error checking {input_str}: {e}")
        return None

def process_file(file_path):
    """
    Process a file containing inputs and check each for potential threats
    :param file_path: Path to the file with inputs
    :return: Dictionary of threats
    """
    threats = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                input_value = line.strip()
                if input_value:
                    # Check input reputation
                    input_alerts = check_reputation(input_value)

                    if input_alerts:
                        threats[input_value] = input_alerts
                        print(f"Potential threat found for: {input_value}")
                        for alert in input_alerts:
                            print(f"  - Name: {alert.get('name', 'Unknown')}")
                            print(f"  - Description: {alert.get('description', 'No description')}")
                            print(f"  - Source: {alert.get('source', 'Unknown')}")
                    else:
                        print(f"No threats found for: {input_value}")
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
    return threats

def main():
    parser = argparse.ArgumentParser(description='Check potential threats using AlienVault OTX')
    parser.add_argument('-file', help='File with inputs to check (hashes, IPs, domains)', required=True)

    args = parser.parse_args()

    # Process the file and check inputs
    threats = process_file(args.file)

    if threats:
        print("\nSummary of Potential Threats:")
        for input_val, threat_details in threats.items():
            print(f"Input: {input_val}")
            for threat in threat_details:
                print(f"  - Name: {threat.get('name', 'Unknown')}")
                print(f"  - Description: {threat.get('description', 'No description')}")
                print(f"  - Source: {threat.get('source', 'Unknown')}")
    else:
        print("No threats found in the file.")

if __name__ == '__main__':
    main()
