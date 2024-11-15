#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse, os, re, sys, copy, requests, warnings, urllib3
from ansible.utils.display import Display
from ansible.errors import AnsibleError, AnsibleLookupError
from urllib3.util import Timeout, Retry

try:
    import json
except ImportError:
    import simplejson as json

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

class dynamic_inventory(object):

    def __init__(self):

        self._display = Display()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Parse CLI arguments
        self.read_cli_args()
        
        # A list of groups and the hosts in that group
        self.inventory = dict()
        
        # Get host vars from API
        api_inventory = self.get_inventory()
        print(json.dumps(api_inventory))

    # Query API
    def query_api(self, dw_url, dw_token):

        try:
            json_obj = {}
            headers  = { "x-api-key": '{}'.format(dw_token),
                         "Content-Type": 'application/json' }

            retries = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout = Timeout(connect=2.0, read=7.0)
            http = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)

            response = http.request(method='GET', url=dw_url, headers=headers)            
            
            if (response.status == 200):
                data = response.data
                json_obj = json.loads(data.decode('utf-8'))
        
            if 'result' in json_obj and json_obj['result'] is not None:
                return json_obj['result']
            else:
                return None
               
        # return empty value if error during request
        except urllib3.exceptions.HTTPError as errh:
             raise AnsibleError('HTTPError: %s' % (errh))
        except urllib3.exceptions.ConnectionError as errc:
            raise AnsibleError('ConnectionError: %s' % (errc))
        except urllib3.exceptions.TimeoutError as errt:
            raise AnsibleError('Timeout: %s' % (errt))
        except urllib3.exceptions.RequestError as err:
            raise AnsibleError('RequestException: %s' % (err))

    # Get Inventory Data from API
    def get_inventory(self):

        # Get python interpreter path for Tower Instance
        if 'ansible_python_interpreter' in os.environ:
            ansible_python_interpreter = os.environ.get('ansible_python_interpreter')
            search_paths = (str(ansible_python_interpreter)).split(':')
        else:
            ansible_python_interpreter = '/usr/bin/python3:/var/lib/awx/SSC/venv/ssc_venv_python3_v2/bin/python'
            search_paths = (ansible_python_interpreter).split(':')
        
        python_path = None

        for path in search_paths:
            if os.path.isfile(path):
                python_path = path
        
        if python_path is None:
            raise AnsibleLookupError('Python Interpreter path not found. Cant continue')
            return

        if 'SSC_TOWER_URL' in os.environ:
            tower_url = str(os.environ.get('SSC_TOWER_URL')).lower()
            tower_url = tower_url.replace("https://","")
        elif 'tower_host' in os.environ:
            tower_url = str(os.environ.get('tower_host'))
            tower_url = tower_url.replace("https://","")
        else:
            raise AnsibleLookupError('Unable to gather tower url.')
            return

        if 'inventory_source_api' in os.environ:
            inventory_source_api = str(os.environ.get('inventory_source_api'))
        else:
            inventory_source_api = 'https://adpdatawarehouse.corp.statestr.com/api/AnsibleServerBuild/AnsibleServerBuildApi'

        if re.search('uat', inventory_source_api, re.IGNORECASE): 
            if 'apidev_token' in os.environ:
                api_token = str(os.environ.get('apidev_token'))
            else:
                raise AnsibleLookupError('Unable to authenticate API using credentials, disabling ssc_data plugin')
                return
        else:
            if 'apiprod_token' in os.environ:
                api_token = str(os.environ.get('apiprod_token'))
            else:
                raise AnsibleLookupError('Unable to authenticate API using credentials, disabling ssc_data plugin')
                return

        inventory = {}
        inventory['_meta'] = {}
        inventory['_meta']['hostvars'] = {}
        inventory['_meta']['hostvars']['localhost'] = {
            'ansible_connection': 'local',
            'ansible_shell_type': 'sh',
            'ansible_python_interpreter': python_path
        }
        inventory['_meta']['hostvars']['gdctwvc0039.uatcorp.uatstatestr.local'] = {
            'ansible_adpwinrm_server_cert_validation': 'ignore',
            'ansible_adpwinrm_transport': 'ntlm',
            'ansible_connection': 'adpwinrm',
            'ansible_port': '5986',
            'ansible_psrp_auth': 'ntlm',
            'ansible_psrp_cert_validation': 'ignore',
            'ansible_shell_type': 'adppowershell',
            'ansible_winrm_server_cert_validation': 'ignore',
            'ansible_winrm_transport': 'ntlm',
            'roles_path': '~/Code/ansible_roles'
        }
        inventory['all'] = {}
        inventory['all']['hosts'] = [
            'localhost',
            'gdctwvc0039.uatcorp.uatstatestr.local'
        ]
        inventory['all']['children'] = ['ungrouped']
        inventory['all']['vars'] = {
            'ansible_shell_type': 'powershell',
            'ansible_connection': 'ssh',
            'ansible_port': 22,
            'roles_path': '~/Code/ansible_roles'
        }
        inventory['ungrouped'] = {}
        inventory['ungrouped']['hosts'] = [
            'localhost',
            'gdctwvc0039.uatcorp.uatstatestr.local'
        ]
        inventory['all_windows_servers'] = {}
        inventory['all_windows_servers']['children'] = []

        api_url = "%s/GetDynamicInventory?TowerInstance=%s" % (inventory_source_api, tower_url)
        inScope = self.query_api(api_url, api_token)
        
        if inScope['hostNames'] and inScope['hostNames'] is not None:
            serverList = inScope['hostNames']

        if serverList and serverList is not None:
            for server in serverList:

                api_url = "%s?ServerName=%s" % (inventory_source_api, server.lower())
                result = self.query_api(api_url, api_token)

                if result and result['inventoryData'] is not None:
                    data = result['inventoryData']
                else:
                    continue

                if 'fqdn' in data and data['fqdn'] is not None:

                    server_group = []
                    fqdn = data['fqdn'].lower()

                    # Add hostname to all:hosts
                    if fqdn not in inventory['all']['hosts']:
                        inventory['all']['hosts'].append(fqdn)

                    # Configure Hostvars
                    if fqdn not in inventory['_meta']['hostvars']:
                        inventory['_meta']['hostvars'][fqdn] = {}

                    if ('operatingEnvironment' in data) and (data['operatingEnvironment'] is not None):
                        operating_environment = str.lower(data['operatingEnvironment']).strip()
                        inventory['_meta']['hostvars'][fqdn]['operatingEnvironment'] = operating_environment
                            
                        # Create Environment Group (if required)
                        if operating_environment not in inventory:
                            inventory[operating_environment] = {}
                            inventory[operating_environment]['hosts'] = []
                            inventory['all']['children'].append(operating_environment)

                        # Add server to Environment Group
                        if fqdn not in inventory[operating_environment]['hosts']:    
                            inventory[operating_environment]['hosts'].append(fqdn)
                            server_group.append(operating_environment)

                    else:
                        inventory['_meta']['hostvars'][fqdn]['operatingEnvironment'] = ""

                    if ('location' in data) and (data['location'] is not None):
                        location = str.lower(data['location']).strip()
                        inventory['_meta']['hostvars'][fqdn]['location'] = location
                    else:
                        inventory['_meta']['hostvars'][fqdn]['location'] = ""

                    if ('domain' in data) and (data['domain'] is not None):
                        domain = str.lower(data['domain']).strip()
                        inventory['_meta']['hostvars'][fqdn]['domain'] = domain
                    else:
                        inventory['_meta']['hostvars'][fqdn]['domain'] = ""
                            
                    if ('hostname' in data) and (data['hostname'] is not None):
                        hostname = str.lower(data['hostname']).strip()
                        inventory['_meta']['hostvars'][fqdn]['hostname'] = hostname  
                    else:
                        inventory['_meta']['hostvars'][fqdn]['hostname'] = ""

                    if ('operatingSystem' in data) and (data['operatingSystem'] is not None):
                        opsys = str.lower(data['operatingSystem']).strip()
                        inventory['_meta']['hostvars'][fqdn]['operatingSystem'] = opsys
                    else:
                        inventory['_meta']['hostvars'][fqdn]['operatingSystem'] = ""

                    if opsys and opsys is not None:
                        matches = re.search('(standard|datacenter)$', opsys)
                        if matches is not None:
                            try:
                                opedition = matches.group(1)
                                inventory['_meta']['hostvars'][fqdn]['operatingSystemEdition'] = opedition.lower()
                            except:
                                inventory['_meta']['hostvars'][fqdn]['operatingSystemEdition'] = ""
                        else:
                            inventory['_meta']['hostvars'][fqdn]['operatingSystemEdition'] = ""
                    else:
                        inventory['_meta']['hostvars'][fqdn]['operatingSystemEdition'] = ""

                    if ('operatingSystemType' in data) and (data['operatingSystemType'] is not None):
                        optype = str.lower(data['operatingSystemType']).strip()
                        inventory['_meta']['hostvars'][fqdn]['operatingSystemType'] = optype
                    else:
                        inventory['_meta']['hostvars'][fqdn]['operatingSystemType'] = ""

                    if ('operatingSystemVersion' in data) and (data['operatingSystemVersion'] is not None):
                        osver = str.lower(data['operatingSystemVersion']).strip()
                        groupver = 'windows' + osver
                        inventory['_meta']['hostvars'][fqdn]['operatingSystemVersion'] = osver

                        if groupver not in inventory:
                            inventory[groupver] = {}
                            inventory[groupver]['hosts'] = []
                            inventory['all']['children'].append(groupver)

                        if groupver not in inventory['all_windows_servers']['children']:
                            inventory['all_windows_servers']['children'].append(groupver)

                        if fqdn not in inventory[groupver]['hosts']:    
                            inventory[groupver]['hosts'].append(fqdn)
                            server_group.append(groupver)

                    else:
                        inventory['_meta']['hostvars'][fqdn]['operatingSystemVersion'] = ""

                    if ('applicationCode' in data) and (data['applicationCode'] is not None):
                        appcode = str.lower(data['applicationCode']).strip()
                        inventory['_meta']['hostvars'][fqdn]['applicationCode'] = appcode
                    else:
                        inventory['_meta']['hostvars'][fqdn]['applicationCode'] = ""

                    if ('ipAddress' in data) and (data['ipAddress'] is not None):
                        ipaddr = str.lower(data['ipAddress']).strip()
                        inventory['_meta']['hostvars'][fqdn]['ipAddress'] = ipaddr
                    else:
                        inventory['_meta']['hostvars'][fqdn]['ipAddress'] = ""

                    if ('region' in data) and (data['region'] is not None):
                        region = str.lower(data['region']).strip()
                        inventory['_meta']['hostvars'][fqdn]['region'] = region
                    else:
                        inventory['_meta']['hostvars'][fqdn]['region'] = ""

                    if ('role' in data) and (data['role'] is not None):
                        role = str.lower(data['role']).strip()
                        inventory['_meta']['hostvars'][fqdn]['role'] = role
                    else:
                        inventory['_meta']['hostvars'][fqdn]['role'] = ""

                    if ('platform' in data) and (data['platform'] is not None):
                        platform = str.lower(data['platform']).strip()
                        inventory['_meta']['hostvars'][fqdn]['platform'] = platform
                    else:
                        inventory['_meta']['hostvars'][fqdn]['platform'] = ""

                    if ('webProxy' in data) and (data['webProxy'] is not None):
                        webProxy = str.lower(data['webProxy']).strip()
                        inventory['_meta']['hostvars'][fqdn]['web_proxy'] = webProxy
                    else:
                        inventory['_meta']['hostvars'][fqdn]['web_proxy'] = ""

                    if server_group is None:
                        if fqdn not in inventory['ungrouped']['hosts']:    
                            inventory['ungrouped']['hosts'].append(fqdn)
                else:
                    continue


        else:
            inventory = self.empty_inventory()
        return inventory

    # Empty inventory for testing.
    def empty_inventory(self):
        return {'_meta': {'hostvars': {}}}

    # Read the command line args passed to the script.
    def read_cli_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--list', action = 'store_true')
        parser.add_argument('--host', action = 'store')
        self.args = parser.parse_args()

# Get the inventory.
dynamic_inventory()
