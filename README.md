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
 - Paste the following python script in the [custom-alienvault.py](https://github.com/effaaykhan/Alienvault_OTX-Integration-with-Wazuh/blob/main/custom-alienvault.py) file or get it by using ```wget``` utility:
```
wget https://github.com/effaaykhan/Alienvault_OTX-Integration-with-Wazuh/blob/main/custom-alienvault.py
```

## get_malicious.py

```bash
   nano get_malicious.py
```
- Paste the following python script in the [get_malicious.py](https://github.com/effaaykhan/Alienvault_OTX-Integration-with-Wazuh/blob/main/get_malicious.py) or download it by using the ```wget``` utility
```
wget https://github.com/effaaykhan/Alienvault_OTX-Integration-with-Wazuh/blob/main/get_malicious.py
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
## Add the following snippet in /var/ossec/etc/ossec.conf
```
  <integration>
    <name>custom-alienvault</name>
    <alert_format>json</alert_format>
    <hook_url>none</hook_url> <!-- Optional: only if needed -->
    <level>3</level>           <!-- CORRECT tag to trigger on alert level -->
  </integration>
```

## Restart the wazuh-manager
```bash
   sudo systemctl restart wazuh-manager
```
