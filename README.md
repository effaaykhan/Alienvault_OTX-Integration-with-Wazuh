# Alienvault_OTX-Integration-with-Wazuh
This Repository contains the Integration guide of Wazuh with Alienvault_OTX

## Make sure that Wazuh have installed OTXv2
   ```bash
      /var/ossec/framework/python/bin/python3 -m pip install OTXv2
   ```
## Create 3 files into /var/ossec/integrations
   ```bash
      cd /var/ossec/integrations/ && touch custom-alienvault custom-alienvault.py get_malicious.py
   ```
## Custom-alienvault
   ```bash
      nano custom-alienvault
   ```
- Paste the following bash script in the custom-alienvault file
  ```bash
     	#!/bin/sh
      WPYTHON_BIN="framework/python/bin/python3"

      SCRIPT_PATH_NAME="$0"

      DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
      SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

      case ${DIR_NAME} in
          */active-response/bin | */wodles*)
              if [ -z "${WAZUH_PATH}" ]; then
                  WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
              fi

      PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
      ;;
      */bin)
          if [ -z "${WAZUH_PATH}" ]; then
              WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
          fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
      ;;
      */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
     ;;
     esac


    ${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
  ```

  ## custom-alienvault.py
  ```bash
     nano custom-alienvault.py
  ```
 - Paste the following python script in the custom-alienvault.py file
  ```bash
  #!/usr/bin/env python

  # Import necessary libraries and modules
  from OTXv2 import OTXv2
  import argparse
  import get_malicious
  import hashlib
  import sys
  import os
  from socket import socket, AF_UNIX, SOCK_DGRAM
  from datetime import date, datetime, timedelta
  import time
  import requests
  from requests.exceptions import ConnectionError
  import json
	
	# Get the current working directory
  pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

  # Define the Unix socket address for sending events
  socket_addr = '{0}/queue/sockets/queue'.format(pwd)

# Function to send an event to the specified socket
def send_event(msg, agent=None):
  if not agent or agent["id"] == "000":
# If no agent or agent ID is "000", format the string accordingly
        string = '1:alienvault_stats:{0}'.format(json.dumps(msg))
    else:
        # If agent information is available, include it in the string
        string = '1:[{0}] ({1}) {2}->alienvault_stats:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    
    # Establish a connection to the Unix socket and send the event
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

# Set boolean value 'false' to False (possibly for later use)
false = False

# Set up AlienVault OTX API key and server URL
API_KEY = 'APIKEY'
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

# Open and read the content of the specified alert file (JSON format)
alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()

# Extract the queried domain name from the alert data
dns_query_name = alert["data"]["win"]["eventdata"]["queryName"]

# Query AlienVault OTX for potential malicious indicators related to the domain
alerts = get_malicious.hostname(otx, dns_query_name)

# Check if there are any alerts
if len(alerts) > 0:
    print('Identified as potentially malicious')
    # Prepare an alert output structure for sending events
    alert_output = {}
    alert_output["alienvault_alert"] = {}
    alert_output["integration"] = "alienvault"
    alert_output["alienvault_alert"]["query"] = dns_query_name
    # Send the event with the alert information
    send_event(alert_output, alert["agent"])
else:
    print('Unknown or not identified as malicious')
```

## get_malicious.py

```bash
   nano get_malicious.py
```
- Paste the following python script in the get_malicious.py
  
```bash
   #!/usr/bin/env python
#  This script tells if a File, IP, Domain or URL may be malicious according to the data in OTX

from OTXv2 import OTXv2
import argparse
import get_malicious
import hashlib


# Your API key
API_KEY = ''
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

parser = argparse.ArgumentParser(description='OTX CLI Example')
parser.add_argument('-ip', help='IP eg; 4.4.4.4', required=False)
parser.add_argument('-host',
                    help='Hostname eg; www.alienvault.com', required=False)
parser.add_argument(
    '-url', help='URL eg; http://www.alienvault.com', required=False)
parser.add_argument(
    '-hash', help='Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571', required=False)
parser.add_argument(
    '-file', help='Path to a file, eg; malware.exe', required=False)

args = vars(parser.parse_args())


if args['ip']:
    alerts = get_malicious.ip(otx, args['ip'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

if args['host']:
    alerts = get_malicious.hostname(otx, args['host'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

if args['url']:
    alerts = get_malicious.url(otx, args['url'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

if args['hash']:
    alerts =  get_malicious.file(otx, args['hash'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')


if args['file']:
    hash = hashlib.md5(open(args['file'], 'rb').read()).hexdigest()
    alerts =  get_malicious.file(otx, hash)
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')
```

## Strings to be included in /var/ossec/etc/ossec.conf
```bash
   nano /var/ossec/etc/ossec.conf
```
- Add the following integration in the ossec.conf file
```bash
<integration>
    <name>custom-alienvault</name>
    <group>sysmon_event_22</group>
    <alert_format>json</alert_format>
</integration>
```

## File to be included in /var/ossec/etc/rules
- Create the rule file for alienvault_OTX
```bash
   nano alienOTX.xml
```
- Add the following rule in the alienOTX.xml
```bash
<group name="alienvault_alert,">
  <rule id="100010" level="12">
    <field name="integration">alienvault</field>
    <description>AlienVault - OTX DOMAIN Found</description>
    <options>no_full_log</options>
  </rule>
</group>
```

## Restart the wazuh-manager
```bash
   sudo systemctl restart wazuh-manager
```
