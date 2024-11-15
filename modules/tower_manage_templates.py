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
module: tower_manage_templates
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Create / Update Job Templates
description:
    See documentation for further information:
    - https://docs.ansible.com/ansible-tower/latest/html/userguide/job_templates.html
'''

import time
import json
import re

from ..module_utils.tower_api import TowerAPIModule

def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        template_details=dict(required=True, type='dict'),
        organization=dict(required=True),
        project_name=dict(required=True, default=None),
        tower_host=dict(required=True, aliases=['host']),
        tower_prefix=dict(required=True, default=None),
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
    
    template_details = module.params.get('template_details')
    project_name     = module.params.get('project_name')
    organization     = module.params.get('organization')
    tower_host       = module.params.get('tower_host')
    tower_prefix     = module.params.get('tower_prefix')

    template_fields = {}
    template_fields['organization'] = module.resolve_name_to_id('organizations', organization)
    template_fields['project'] = module.resolve_name_to_id('projects', project_name)

    # configure template_name
    if 'name' in template_details:
        template_name = tower_prefix + '_' + template_details['name']
        template_fields['name'] = template_name
    else:
        module.fail_json(msg="name parameter not passed in within dict 'template_details'")

    # configure template_inventory
    if 'inventory' in template_details:
        template_inventory = tower_prefix + '_' + template_details['inventory']
        template_fields['inventory'] = module.resolve_name_to_id('inventories', template_inventory)
    else:
        module.fail_json(msg="inventory parameter not passed in within dict 'template_details'")

    # configure template_type
    if 'type' in template_details:
        template_type = template_details['type']
    else:
        module.fail_json(msg="type parameter not passed in within dict 'template_details'")

    # configure template_description
    if 'description' in template_details:
        template_description = template_details['description']
        template_fields['description']  = template_description
    else:
        module.fail_json(msg="description parameter not passed in within dict 'template_details'")

    # configure template_config
    if 'config' in template_details:
        template_config = template_details['config']
        template_fields.update(template_config)
    else:
        module.fail_json(msg="config parameter not passed in within dict 'template_details'")

    # if on UAT or PROD, disallow overriding of branches
    if 'UAT' in tower_prefix or 'PRD' in tower_prefix:
        template_fields['ask_scm_branch_on_launch'] = False

    # ----------------------
    # START
    # ----------------------
    
    # Get template details
    endpoints = module.get_endpoint(endpoint='/')
    template  = module.get_one(endpoint=template_type, name_or_id=template_name, data={'organization': template_fields['organization']})

    # Check Values
    for element in template_fields:
        if element is None:
            module.fail_json(msg='{0} param in template_config dict not passed into the module. Unable to continue.'.format(element))

    # Create / Update Template
    if template:
        # Perform an update to existing template
        result = module.make_request(method='PUT', endpoint=template['url'],**{'data': template_fields})
        
        if result['status_code'] != 200:        
            module.fail_json(msg="Failed to update template, see response for details", response=result)
    else:
        # Create new template
        result = module.post_endpoint(endpoints['json'][template_type],**{'data': template_fields})

        if result['status_code'] != 201:        
            module.fail_json(msg="Failed to create template, see response for details", response=result)

        template = module.get_one(endpoint=template_type, name_or_id=template_name, data={'organization': template_fields['organization']})

    # Add survey spec details
    if 'spec' in template_details:
        template_fields['spec'] = template_details['spec']
        result = module.post_endpoint(template['related']['survey_spec'],**{'data': template_fields})
        if result['status_code'] != 200:
            module.fail_json(msg="Failed to update template, see response for details", response=result)

    # Get legacy schedules & Remove for template
    scheduleList = module.make_request(method='GET', endpoint=template['related']['schedules'])
    if 'results' in scheduleList['json']:
        for obj in scheduleList['json']['results']:
            if 'id' in obj:
                result = module.make_request(method='DELETE', endpoint=obj['url'],**{'data': { 'id': obj['id'] } })
                if result['status_code'] != 204:
                    module.fail_json(msg="Failed to update template, see response for details", response=result)
    
    # Add any required schedules
    if 'schedule' in template_details:
        for sched in template_details['schedule']:
            if 'name' in sched:
                result = module.post_endpoint(template['related']['schedules'],**{'data': sched})
                if result['status_code'] != 201:
                    module.fail_json(msg="Failed to update template, see response for details", response=result)
   
    # Get legacy credentials & Remove for template
    creds = module.make_request(method='GET', endpoint=template['related']['credentials'])
    if 'results' in creds['json']:
        for obj in creds['json']['results']:
            name = obj['name']
            disassociate_cred = {}
            disassociate_cred['id'] = module.resolve_name_to_id('credentials', name)
            disassociate_cred['disassociate'] = True
            result = module.post_endpoint(template['related']['credentials'],**{'data': disassociate_cred})
    
    # Add any required credentials
    if 'credentials' in template_details:
        credential_list = module.make_request(method='GET', endpoint=endpoints['json']['credentials'])
        for credential in template_details['credentials']:
            if 'name' in credential:
                if 'results' in credential_list['json']:
                    found = False
                    for x in credential_list['json']['results']:
                        if 'name' in x:
                            if credential['name'].lower() in x['name'].lower():
                                credential['match']     = x['name']
                                credential['id']        = module.resolve_name_to_id('credentials', x['name'])
                                credential['associate'] = True

                                result = module.post_endpoint(template['related']['credentials'],**{'data': credential})
                                if result['status_code'] != 204:
                                    module.fail_json(msg="Failed to update template, see response for details", response=result)

                                found = True
                                break
                    if not found:
                        module.fail_json(msg='Credential object not found.')
                else:
                    module.fail_json(msg='No Credentials found in organisation.')
            else:
                module.fail_json(msg='Credential object not passed in correctly: Missing name. Unable to continue.')

    module.json_output['changed'] = True
    module.json_output['template_name'] = template_name
    module.json_output['template_type'] = template_type
    module.json_output['template_description'] = template_description

    module.exit_json(**module.json_output)

if __name__ == '__main__':
    main()
