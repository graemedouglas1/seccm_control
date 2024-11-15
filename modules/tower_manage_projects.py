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
module: tower_manage_projects
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Create / Update Projects
description:
    See documentation for further information:
    - https://docs.ansible.com/ansible-tower/latest/html/userguide/projects.html
'''

import time
import json
import re

from ..module_utils.tower_api import TowerAPIModule

def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        project_details=dict(required=True, type='dict'),
        organization=dict(required=True),
        tower_prefix=dict(required=True, default=None),
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
    
    project_details = module.params.get('project_details')
    tower_prefix    = module.params.get('tower_prefix')
    organization    = module.params.get('organization')
    tower_host      = module.params.get('tower_host')

    project_fields = {}
    project_fields['organization'] = module.resolve_name_to_id('organizations', organization)
    project_fields['credential'] = module.resolve_name_to_id('credentials', project_details['credential'])

    # configure project_name
    if 'name' in project_details:
        project_name = tower_prefix + '_' + project_details['name']
        project_fields['name'] = project_name
    else:
        module.fail_json(msg="name parameter not passed in within dict 'project_details'")

    # configure project_description
    if 'description' in project_details:
        project_description = project_details['description']
        project_fields['description']  = project_description
    else:
        module.fail_json(msg="description parameter not passed in within dict 'project_details'")

    # configure project_config
    if 'config' in project_details:
        project_config = project_details['config']
        project_fields.update(project_config)
    else:
        module.fail_json(msg="config parameter not passed in within dict 'project_details'")

    # if on UAT or PROD, disallow updating of projects automatically
    if 'UAT' in tower_prefix or 'PRD' in tower_prefix:
        project_fields['scm_update_on_launch'] = False

    # ----------------------
    # START
    # ----------------------
    
    # Get project details
    endpoints = module.get_endpoint(endpoint='/')
    project   = module.get_one(endpoint='projects', name_or_id=project_name, data={'organization': project_fields['organization']})

    # Check Values
    for element in project_fields:
        if element is None:
            module.fail_json(msg='{0} param in project_config dict not passed into the module. Unable to continue.'.format(element))

    # Create / Update Project
    if project:
        # Perform an update to existing Project
        result = module.make_request(method='PUT', endpoint=project['url'],**{'data': project_fields})
        
        if result['status_code'] != 200:        
            module.fail_json(msg="Failed to update project, see response for details", response=result)
    else:
        # Create new project
        result = module.post_endpoint(endpoints['json']['projects'],**{'data': project_fields})

        if result['status_code'] != 201:        
            module.fail_json(msg="Failed to create project, see response for details", response=result)

        project = module.get_one(endpoint='projects', name_or_id=project_name, data={'organization': project_fields['organization']})

    module.json_output['changed'] = True
    module.json_output['project_name'] = project_name
    module.json_output['project_description'] = project_description

    module.exit_json(**module.json_output)

if __name__ == '__main__':
    main()
