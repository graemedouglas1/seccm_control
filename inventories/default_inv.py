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

class defaultInventory(object):

    def __init__(self):

        # Parse CLI arguments
        self.read_cli_args()
        
        # A list of groups and the hosts in that group
        self.inventory = dict()
        
        # Get host vars from Data Warehouse
        default_inventory = self.get_inventory()
        print(json.dumps(default_inventory))

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
            'localhost',
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
        ]
        inventory['all_hosts'] = {}
        inventory['all_hosts']['children'] = []
        
        return inventory
    
    def empty_inventory(self):
        return {'_meta': {'hostvars': {}}}

    # Read the command line args passed to the script.
    def read_cli_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--list', action = 'store_true')
        parser.add_argument('--host', action = 'store')
        self.args = parser.parse_args()

# Get the inventory.
defaultInventory()
