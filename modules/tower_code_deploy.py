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
module: tower_code_deploy
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Deploy Project SCM
description:
    See documentation for further information:
    - https://docs.ansible.com/ansible-tower/latest/html/userguide/projects.html
'''

import time

from ..module_utils.tower_api import TowerAPIModule

def wait_for_project_update(module, last_request):
    # The current running job for the update is in last_request['summary_fields']['current_update']['id']

    # Get parameters that were not passed in
    update_project = module.params.get('update_project')
    wait = module.params.get('wait')
    timeout = module.params.get('timeout')
    interval = module.params.get('interval')

    if 'current_update' in last_request['summary_fields']:
        running = True
        while running:     
            result = module.get_endpoint('/project_updates/{0}/'.format(last_request['summary_fields']['current_update']['id']))['json']

            if module.is_job_done(result['status']):
                time.sleep(1)
                running = False

        if result['status'] != 'successful':
            module.fail_json(msg="Project update failed")
    elif update_project:
        result = module.post_endpoint(last_request['related']['update'])

        if result['status_code'] != 202:
            module.fail_json(msg="Failed to update project, see response for details", response=result)

        if not wait:
            module.exit_json(**module.json_output)

        # Grab our start time to compare against for the timeout
        start = time.time()

        # Invoke wait function
        module.wait_on_url(
            url=result['json']['url'],
            object_name=module.get_item_name(last_request),
            object_type='Project Update',
            timeout=timeout, interval=interval
        )

    module.exit_json(**module.json_output)


def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        name=dict(required=True, aliases=['project']),
        tower_host=dict(required=True, aliases=['host']),
        organization=dict(),
        scm_branch=dict(aliases=['branch']),
        master_branch=dict(default=None),
        interval=dict(default=1.0, type='float'),
        update_project=dict(default=True, type='bool'),
        notification_templates_started=dict(type="list", elements='str'),
        notification_templates_success=dict(type="list", elements='str'),
        notification_templates_error=dict(type="list", elements='str'),
        wait=dict(default=False, type='bool'),
        timeout=dict(default=600, type='int'),
        validate_certs=dict(default=False, type='bool'),
    )
    
    # Create a module for ourselves
    module = TowerAPIModule(argument_spec=argument_spec)

    # ----------------------
    # PARAMETERS
    # ----------------------
    
    # Extract our parameters
    name            = module.params.get('name')
    tower_host      = module.params.get('tower_host')
    organization    = module.params.get('organization')
    wait            = module.params.get('wait')
    interval        = module.params.get('interval')
    timeout         = module.params.get('timeout')
    update_project  = module.params.get('update_project')
    master_branch   = module.params.get('master_branch')
    scm_branch      = module.params.get('scm_branch')

    # Attempt to look up project based on the provided name or id
    lookup_data = {}
    if organization:
        lookup_data['organization'] = module.resolve_name_to_id('organizations', organization)
        project = module.get_one('projects', name_or_id=name, data=lookup_data)
    if project is None:
        module.fail_json(msg="Unable to find project")

    # Attempt to look up associated field items the user specified.
    association_fields = {}

    notifications_start = module.params.get('notification_templates_started')
    if notifications_start is not None:
        association_fields['notification_templates_started'] = []
        for item in notifications_start:
            association_fields['notification_templates_started'].append(module.resolve_name_to_id('notification_templates', item))

    notifications_success = module.params.get('notification_templates_success')
    if notifications_success is not None:
        association_fields['notification_templates_success'] = []
        for item in notifications_success:
            association_fields['notification_templates_success'].append(module.resolve_name_to_id('notification_templates', item))

    notifications_error = module.params.get('notification_templates_error')
    if notifications_error is not None:
        association_fields['notification_templates_error'] = []
        for item in notifications_error:
            association_fields['notification_templates_error'].append(module.resolve_name_to_id('notification_templates', item))    
        
    # Create the data that gets sent for update
    code_deploy_fields = { }
    
    if master_branch is not None:
        code_deploy_fields['master_branch'] = master_branch
    else:
        code_deploy_fields['master_branch'] = project['scm_branch']
        
    if scm_branch is not None:
        code_deploy_fields['scm_branch'] = scm_branch
    else:
        code_deploy_fields['scm_branch'] = code_deploy_fields['master_branch']

    # If scm_branch is same as currently set project branch, perform update
    if (project['scm_branch'] == code_deploy_fields['scm_branch']):
    
        # Update the project
        result = module.post_endpoint(project['related']['update'])

        if result['status_code'] != 202:
            
            # Change the Project SCM Branch if differs from master_branch
            if (project['scm_branch'] != code_deploy_fields['master_branch']):
                status = module.revert_branch(
                    scm_branch=code_deploy_fields['master_branch'],
                    url=project['url']
                )
              
            module.fail_json(msg="Failed to update project, see response for details", response=result)

        module.json_output['changed'] = True
        module.json_output['id'] = result['json']['id']
        module.json_output['status'] = result['json']['status']
        module.json_output['url'] = result['json']['url']

        # Change the Project SCM Branch if differs from master_branch
        if (project['scm_branch'] != code_deploy_fields['master_branch']):
            status = module.revert_branch(
                scm_branch=code_deploy_fields['master_branch'],
                url=project['url']
            )

        if not wait:
            module.exit_json(**module.json_output)

        # Grab our start time to compare against for the timeout
        start = time.time()

        # Invoke wait function
        module.wait_on_url(
            url=result['json']['url'],
            object_name=module.get_item_name(project),
            object_type='Project Update',
            timeout=timeout, interval=interval
        )

        module.exit_json(**module.json_output)
    
    # scm_branch differs from project branch, change project branch before triggering update 
    else:
      
        if update_project is not None:
            code_deploy_fields['update_project'] = update_project  
    
        # An on_change function, if registered, will fire after an post_endpoint or update_if_needed completes successfully
        on_change = None
        if wait and project['scm_type'] != '' or update_project and project['scm_type'] != '':
            on_change = wait_for_project_update
      
        # If the state was present and we can let the module build or update the existing project, this will return on its own
        module.create_or_update_if_needed(
            project, code_deploy_fields,
            endpoint='projects', item_type='project',
            associations=association_fields,
            on_create=on_change, on_update=on_change
        )

if __name__ == '__main__':
    main()
