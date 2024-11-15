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
module: tower_manage_workflows
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Create / Update Workflow Templates
description:
    See documentation for further information:
    - https://docs.ansible.com/ansible-tower/latest/html/userguide/workflow_templates.html
'''

import time
import json
import re

from ..module_utils.tower_api import TowerAPIModule

def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        organization=dict(required=True),
        project_name=dict(required=True),
        tower_host=dict(required=True, aliases=['host']),
        tower_prefix=dict(required=True, default=None),
        tower_username=dict(required=True, aliases=['username']),
        tower_password=dict(required=True, aliases=['password'], no_log=True),
        workflow_details=dict(required=True, type='dict'),
        timeout=dict(default=600, type='int'),
        validate_certs=dict(default=False, type='bool'),
    )
    
    # Create a module for ourselves
    module = TowerAPIModule(argument_spec=argument_spec)
    
    # ----------------------
    # PARAMETERS
    # ----------------------
    
    workflow_details = module.params.get('workflow_details')
    project_name     = module.params.get('project_name')
    organization     = module.params.get('organization')
    tower_host       = module.params.get('tower_host')
    tower_prefix     = module.params.get('tower_prefix')
    
    workflow_fields = {}
    workflow_fields['organization'] = module.resolve_name_to_id('organizations', organization)
    workflow_fields['project'] = module.resolve_name_to_id('projects', project_name)
    
    # configure workflow_name
    if 'name' in workflow_details:
        workflow_name = tower_prefix + '_' + workflow_details['name']
        workflow_fields['name'] = workflow_name
    else:
        module.fail_json(msg="name parameter not passed in within dict 'workflow_details'")
    
    # configure workflow_inventory
    if 'inventory' in workflow_details:
        workflow_inventory = tower_prefix + '_' + workflow_details['inventory']
        workflow_fields['inventory'] = module.resolve_name_to_id('inventories', workflow_inventory)
    else:
        module.fail_json(msg="inventory parameter not passed in within dict 'workflow_details'")

    # configure workflow_type
    if 'type' in workflow_details:
        workflow_type = workflow_details['type']
    else:
        module.fail_json(msg="type parameter not passed in within dict 'workflow_details'")
        
    # configure workflow_description
    if 'description' in workflow_details:
        workflow_description = workflow_details['description']
        workflow_fields['description'] = workflow_description
    else:
        module.fail_json(msg="description parameter not passed in within dict 'workflow_details'")
        
    # configure workflow_config
    if 'config' in workflow_details:
        workflow_config = workflow_details['config']
        workflow_fields.update(workflow_config)
    else:
        module.fail_json(msg="config parameter not passed in within dict 'workflow_details'")
   
    # if on UAT or PROD, disallow overriding of branches
    if 'UAT' in tower_prefix or 'PRD' in tower_prefix:
        workflow_fields['ask_scm_branch_on_launch'] = False

    # ----------------------
    # START
    # ----------------------
        
    # Get template details
    endpoints = module.get_endpoint(endpoint='/')
    template = module.get_one(endpoint=workflow_type, name_or_id=workflow_name, data={'organization': workflow_fields['organization']})

    # Create / Update Template
    if template:
        # Perform an update to existing template
        result = module.make_request(method='PUT', endpoint=template['url'],**{'data': workflow_fields})
        
        if result['status_code'] != 200:        
            module.fail_json(msg="Failed to update template, see response for details", response=result)
    else:
        # Create new template
        result = module.post_endpoint(endpoints['json'][workflow_type],**{'data': workflow_fields})
  
        if result['status_code'] != 201:        
            module.fail_json(msg="Failed to create template, see response for details", response=result)
        
        template = module.get_one(endpoint=workflow_type, name_or_id=workflow_name, data={'organization': workflow_fields['organization']})

    # Add survey spec details
    if 'spec' in workflow_details:
        spec_fields = { 'name': workflow_details['name'], 'description': workflow_details['description'], 'spec': workflow_details['spec'] }
        result = module.post_endpoint(template['related']['survey_spec'],**{'data': spec_fields})

        if result['status_code'] != 200:        
            module.fail_json(msg="Failed to update template, see response for details", response=result)

    # Add schedule details
    if 'schedule' in workflow_details:
      
        wf_sched = module.make_request(method='GET', endpoint=template['related']['schedules'])
        if 'results' in wf_sched['json']:
            for obj in wf_sched['json']['results']:
                search_fields = {'id': obj['id'], 'unified_job_template': obj['unified_job_template'] }
                existing_item = module.get_one('schedules', **{'data': search_fields})
                result = module.delete_if_needed(existing_item, on_delete=True)
      
        for item in workflow_details['schedule']:
            item['inventory'] = workflow_fields['inventory']

            result = module.post_endpoint(template['related']['schedules'],**{'data': item})

            if result['status_code'] != 201:        
                module.fail_json(msg="Failed to update template, see response for details", response=result)   
            
    # Update Workflow Job with associated templates
    if 'nodes' in workflow_details:

        # Clear Node Template Details
        wf_nodes = module.make_request(method='GET', endpoint=template['related']['workflow_nodes'])
        if 'results' in wf_nodes['json']:
            for obj in wf_nodes['json']['results']:
                identifier = obj['identifier']
                search_fields = {'identifier': identifier, 'workflow_job_template': template['id'] }
                existing_item = module.get_one('workflow_job_template_nodes', **{'data': search_fields})
                result = module.delete_if_needed(existing_item, on_delete=True)

        # Add Workflow Nodes    
        for item in workflow_details['nodes']:
            if 'name' in item:
                new_name = tower_prefix + '_' + item['name']
                identifier = item['identifier']
                
                if 'WFL' in item['name']:
                    unified_job_template = module.resolve_name_to_id('workflow_job_templates', new_name)
                else:
                    unified_job_template = module.resolve_name_to_id('job_templates', new_name)

                job_template = {'identifier': identifier, 'unified_job_template': unified_job_template }
                result = module.post_endpoint(template['related']['workflow_nodes'],**{'data': job_template})
               
                if result['status_code'] != 201:
                    module.fail_json(msg="Failed to associate template, see response for details", response=result)

                if 'credentials' in item:
                    search_fields   = {'identifier': identifier, 'workflow_job_template': template['id']}
                    existing_item   = module.get_one('workflow_job_template_nodes', **{'data': search_fields})
                    credential_list = module.make_request(method='GET', endpoint=endpoints['json']['credentials'])
              
                    for credential in item['credentials']:
                        if 'results' in credential_list['json']:
                            found = False
                            cobj = {}
                            for x in credential_list['json']['results']:
                                if 'name' in x:
                                    if credential.lower() in x['name'].lower():
                                        cobj['id'] = module.resolve_name_to_id('credentials', x['name'])
                                        result     = module.post_endpoint(existing_item['related']['credentials'],**{'data': cobj})
                                        if result['status_code'] != 204:
                                            module.fail_json(msg="Failed to update template, see response for details", response=result)
                                        found = True
                                        break
                            if not found:
                                module.fail_json(msg='Credential object not found.')
                        else:
                            module.fail_json(msg='No Credentials found in organisation.')             

        # Associate Workflow Nodes
        for item in workflow_details['nodes']:

            # Extract our parameters
            new_fields    = {}
            identifier    = item['identifier']
            search_fields = {'identifier': identifier}

            workflow_job_template_id = template['id']
            search_fields['workflow_job_template'] = new_fields['workflow_job_template'] = workflow_job_template_id

            # Attempt to look up an existing item based on the provided data
            existing_item = module.get_one('workflow_job_template_nodes', **{'data': search_fields})
            
            new_fields['unified_job_template'] = module.resolve_name_to_id('unified_job_templates', tower_prefix + '_' + item['name'])

            # Create the data that gets sent for create and update
            for field_name in (
                'identifier',
                'extra_data',
                'scm_branch',
                'job_type',
                'job_tags',
                'skip_tags',
                'limit',
                'diff_mode',
                'verbosity',
                'all_parents_must_converge',
                'forks',
                'job_slice_count',
                'timeout',
            ):
 
                if field_name in item:
                    new_fields[field_name] = item[field_name]
            
            association_fields = {}
            for association in ('always_nodes', 'success_nodes', 'failure_nodes', 'credentials', 'instance_groups', 'labels'):
                name_list = None
                if 'related' in item:
                    if association in item['related']:
                        name_list = item['related'][association]

                if name_list is None:
                    continue
                id_list = []
                for sub_name in name_list:
                    if association in ['credentials', 'instance_groups', 'labels']:
                        sub_obj = module.get_one(association, name_or_id=sub_name)
                    else:
                        endpoint = 'workflow_job_template_nodes'
                        lookup_data = {'identifier': sub_name}
                        if workflow_job_template_id:
                            lookup_data['workflow_job_template'] = workflow_job_template_id
                        sub_obj = module.get_one(endpoint, **{'data': lookup_data})
                    if sub_obj is None:
                        module.fail_json(msg='Could not find {0} entry with name {1}'.format(association, sub_name))
                    id_list.append(sub_obj['id'])
                association_fields[association] = id_list

            execution_environment = module.params.get('execution_environment')
            if execution_environment is not None:
                if execution_environment == '':
                    new_fields['execution_environment'] = ''
                else:
                    ee = module.get_one('execution_environments', name_or_id=execution_environment)
                    if ee is None:
                        module.fail_json(msg='could not find execution_environment entry with name {0}'.format(execution_environment))
                    else:
                        new_fields['execution_environment'] = ee['id']
                
            # In the case of a new object, the utils need to know it is a node
            new_fields['type'] = 'workflow_job_template_node'
                     
            # If the state was present and we can let the module build or update the existing item, this will return on its own
            result = module.create_or_update_if_needed(
                existing_item,
                new_fields,
                endpoint='workflow_job_template_nodes',
                item_type='workflow_job_template_node',
                associations=association_fields,
                return_json=True,
            )

    module.json_output['changed'] = True
    module.json_output['workflow_name'] = workflow_name
    module.json_output['workflow_type'] = workflow_type
    module.json_output['workflow_description'] = workflow_description

    module.exit_json(**module.json_output)

if __name__ == '__main__':
    main()
