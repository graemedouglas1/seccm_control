#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
import os
import re
import sys
import copy
import warnings

try:
    import json
except ImportError:
    import simplejson as json

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

class jenkins_inventory(object):

    def __init__(self):

        # Parse CLI arguments
        self.read_cli_args()
        
        # A list of groups and the hosts in that group
        self.inventory = dict()
        
        # Get host vars from API
        api_inventory = self.get_inventory()
        print(json.dumps(api_inventory))

    # Get Inventory Data from API
    def get_inventory(self):
        
        # Get python interpreter path for Tower Instance
        if 'ansible_python_interpreter' in os.environ:
            ansible_python_interpreter = os.environ.get('ansible_python_interpreter')
            search_paths = (str(ansible_python_interpreter)).split(':')
        else:
            ansible_python_interpreter = '/usr/bin/python3.11:/var/lib/awx/SSC/venv/ssc_venv_python3_v2/bin/python'
            search_paths = (ansible_python_interpreter).split(':')
        
        python_path = None

        for path in search_paths:
            if os.path.isfile(path):
                python_path = path
        
        if python_path is None:
            raise AnsibleLookupError('Python Interpreter path not found. Cant continue')
            return

        inventory = {}
        inventory['_meta'] = {}
        inventory['_meta']['hostvars'] = {}
        inventory['_meta']['hostvars']['localhost'] = {
            'ansible_connection': 'local',
            'ansible_shell_type': 'sh',
            'ansible_python_interpreter': python_path
        }
        inventory['all'] = {}
        inventory['all']['hosts'] = [
            'localhost'
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
            'localhost'
        ]
        inventory['all_hosts'] = {}
        inventory['all_hosts']['children'] = []

        
        serverList = ['ansible01.togher.com']
        
        if serverList and serverList is not None:
            for server in serverList:
                
                result = {
                    'inventoryData': {
                      'fqdn': 'ansible01.togher.com',
                      'ipaddress': '10.0.0.247',
                      'os_family': 'windows',
                      'domain': 'togher',
                      'domain_fqdn': 'togher.com',
                      'application': 'jenkins',
                      'ansible_connection': 'winrm',
                      'ansible_port': '5986'
                    },
                    
                }

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

                    if 'fqdn' not in inventory['_meta']['hostvars'][fqdn]:
                        inventory['_meta']['hostvars'][fqdn]['fqdn'] = fqdn

                    if ('ipaddress' in data) and (data['ipaddress'] is not None):
                        ipaddr = str.lower(data['ipaddress']).strip()
                        inventory['_meta']['hostvars'][fqdn]['ipaddress'] = ipaddr
                    else:
                        inventory['_meta']['hostvars'][fqdn]['ipaddress'] = ""

                    if ('os_family' in data) and (data['os_family'] is not None):
                        osfamily = str.lower(data['os_family']).strip()
                        inventory['_meta']['hostvars'][fqdn]['os_family'] = osfamily
                       
                        if osfamily not in inventory:
                            inventory[osfamily] = {}
                            inventory[osfamily]['hosts'] = []
                            inventory['all']['children'].append(osfamily)

                        if osfamily not in inventory['all_hosts']['children']:
                            inventory['all_hosts']['children'].append(osfamily)

                        if fqdn not in inventory[osfamily]['hosts']:    
                            inventory[osfamily]['hosts'].append(fqdn)
                            server_group.append(osfamily)

                    else:
                        inventory['_meta']['hostvars'][fqdn]['os_family'] = ""

                    if ('domain' in data) and (data['domain'] is not None):
                        domain = str.lower(data['domain']).strip()
                        inventory['_meta']['hostvars'][fqdn]['domain'] = domain
                    else:
                        inventory['_meta']['hostvars'][fqdn]['domain'] = ""

                    if ('domain_fqdn' in data) and (data['domain_fqdn'] is not None):
                        domainfqdn = str.lower(data['domain_fqdn']).strip()
                        inventory['_meta']['hostvars'][fqdn]['domain_fqdn'] = domainfqdn
                    else:
                        inventory['_meta']['hostvars'][fqdn]['domain_fqdn'] = ""

                    if ('ansible_connection' in data) and (data['ansible_connection'] is not None):
                        ansible_conn = str.lower(data['ansible_connection']).strip()
                        inventory['_meta']['hostvars'][fqdn]['ansible_connection'] = ansible_conn

                    if ('ansible_port' in data) and (data['ansible_port'] is not None):
                        ansible_port = str.lower(data['ansible_port']).strip()
                        inventory['_meta']['hostvars'][fqdn]['ansible_port'] = ansible_port

                    if ('application' in data) and (data['application'] is not None):
                        application = str.lower(data['application']).strip()
                        inventory['_meta']['hostvars'][fqdn]['application'] = application
                    
                        if application not in inventory:
                            inventory[application] = {}
                            inventory[application]['hosts'] = []
                            inventory['all']['children'].append(application)

                        if application not in inventory['all_hosts']['children']:
                            inventory['all_hosts']['children'].append(application)

                        if fqdn not in inventory[application]['hosts']:    
                            inventory[application]['hosts'].append(fqdn)
                            server_group.append(application)

                    else:
                        inventory['_meta']['hostvars'][fqdn]['application'] = ""


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
jenkins_inventory()
