#!/usr/bin/python
# coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
  'metadata_version': '1.0',
  'status': 'preview',
  'supported_by': 'GCS SecCM (Security Config Management) Team - State Street Corporation'
}

DOCUMENTATION = '''
---
module: tower_manage_inventories
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Create / Update Inventories
description:
    See documentation for further information:
    - https://docs.ansible.com/ansible-tower/latest/html/userguide/inventories.html
'''

import time
import json
import re
import logging

from ..module_utils.tower_api import TowerAPIModule

def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        inventory_details=dict(required=True, type='dict'),
        inventory_sources=dict(required=True, type='dict'),
        organization=dict(required=True),
        tower_prefix=dict(required=True, default=None),
        tower_instance=dict(required=True),
        tower_host=dict(required=True, aliases=['host']),
        tower_username=dict(required=True, aliases=['username']),
        tower_password=dict(required=True, aliases=['password'], no_log=True),
        timeout=dict(default=600, type='int'),
        validate_certs=dict(default=False, type='bool'),
    )
    
    # Create a module for ourselves
    module = TowerAPIModule(argument_spec=argument_spec)
                            
    # ----------------------
    # PARAMETERS
    # ----------------------
    
    inventory_details = module.params.get('inventory_details')
    inventory_sources = module.params.get('inventory_sources')
    tower_prefix      = module.params.get('tower_prefix')
    tower_instance    = module.params.get('tower_instance')
    organization      = module.params.get('organization')
    tower_host        = module.params.get('tower_host')

    inventory_fields = {}
    inventory_fields['organization'] = module.resolve_name_to_id('organizations', organization)

    # configure inventory_name
    if 'name' in inventory_details:
        inventory_name = tower_prefix + '_' + inventory_details['name']
        inventory_fields['name'] = inventory_name
    else:
        module.fail_json(msg="name parameter not passed in within dict 'inventory_details'")

    # configure inventory_description
    if 'description' in inventory_details:
        inventory_description = inventory_details['description']
        inventory_fields['description']  = inventory_description
    else:
        module.fail_json(msg="description parameter not passed in within dict 'inventory_details'")

    # configure inventory_variables
    if 'variables' in inventory_details:
        inventory_variables = inventory_details['variables']
        inventory_fields['variables']  = inventory_variables
    else:
        module.fail_json(msg="variables parameter not passed in within dict 'inventory_details'")
        
    # ----------------------
    # START
    # ----------------------
    
    # Get inventory details
    endpoints = module.get_endpoint(endpoint='/')
    inventory = module.get_one(endpoint='inventories', name_or_id=inventory_name, data={'organization': inventory_fields['organization']})

    # Check Values
    for element in inventory_fields:
        if element is None:
            module.fail_json(msg='{0} param in inventory_config dict not passed into the module. Unable to continue.'.format(element))

    # Create / Update inventory
    if inventory:
        # Perform an update to existing inventory
        result = module.make_request(method='PUT', endpoint=inventory['url'],**{'data': inventory_fields})
        
        if result['status_code'] != 200:        
            module.fail_json(msg="Failed to update inventory, see response for details", response=result)
    else:
        # Create new inventory
        result = module.post_endpoint(endpoints['json']['inventory'],**{'data': inventory_fields})

        if result['status_code'] != 201:        
            module.fail_json(msg="Failed to create inventory, see response for details", response=result)

        inventory = module.get_one(endpoint='inventories', name_or_id=inventory_name, data={'organization': inventory_fields['organization']})
    
    # Create / Update inventory sources
    inventory_name = inventory_details['name']
    
    for index, (key, value) in enumerate(inventory_sources.items()):
        if inventory_name == key:
            for v in value:                
                if tower_instance in v['instance']:

                    if 'credential' in v and v['credential'] is not None and v['credential'] != '':
                        test = '{0}_{1}'.format(tower_prefix, v['credential'])
                        v['credential'] = module.resolve_name_to_id('credentials', test)

                    # Set additional details
                    inventory_project   = tower_prefix + '_' + str(v['source_project'])
                    v['inventory']      = inventory['id']
                    v['source_project'] = module.resolve_name_to_id('projects', inventory_project)

                    # Check existance
                    src = module.get_one(endpoint='inventory_sources', name_or_id=v['name'], data={'organization': inventory_fields['organization']})

                    if src:
                        # Perform an update to existing source
                        result = module.make_request(method='PUT', endpoint=src['url'],**{'data': v})

                        if result['status_code'] != 200:        
                            module.fail_json(msg="Failed to update inventory source, see response for details", response=result)
                    else:            
                        # Create new source on inventory
                        result = module.post_endpoint(endpoints['json']['inventory_sources'],**{'data': v})

                        if result['status_code'] != 201:        
                            module.fail_json(msg="Failed to create inventory source, see response for details", response=result)

                        src = module.get_one(endpoint='inventory_sources', name_or_id=v['name'], data={'organization': inventory_fields['organization']})            

                    # Start Sync Process
                    #sourceList = module.make_request(method='GET', endpoint=inventory['related']['update_inventory_sources'])
                    if src:
                        if 'id' in src:
                            result = module.make_request(method='POST', endpoint=src['related']['update'],**{'data': { 'id': src['id'] } })
                            if result['status_code'] != 202:
                                module.fail_json(msg="Failed to trigger inventory source update, see response for details", response=result)

    module.json_output['changed'] = True
    module.json_output['inventory_name'] = inventory_name
    module.json_output['inventory_description'] = inventory_description

    module.exit_json(**module.json_output)

if __name__ == '__main__':
    main()
