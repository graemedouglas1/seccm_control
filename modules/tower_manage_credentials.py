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
module: tower_manage_credentials
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Create / Update Credentials
description:
    See documentation for further information:
    - https://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html
'''

import time
import json
import re
import os
import ssl
import urllib3
import datetime
import logging

from urllib3.util import Timeout, Retry
from ansible.utils.display import Display
from ..module_utils.tower_api import TowerAPIModule

system_tracking_logger = logging.getLogger('ssc.modules.tower_manage_credentials')

def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        credential_details=dict(required=True, type='dict'),
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
    _display = Display()
    
    def _get_auth_token(url, encoded_body):
        try:
            retries  = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout  = Timeout(connect=2.0, read=7.0)
            http     = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)
            response = http.request(method='POST', url=url, body=encoded_body)  

            _display.v("Token Status: {0}".format(response.status))

            if (response.status == 200):
                data         = response.data
                json_obj     = json.loads(data)
                client_token = str(json_obj['auth']['client_token'])
              
                return client_token
            else:
                error_msg = "AuthToken Not Provided by Service. Please Check Details and Try Again."
                system_tracking_logger.error("Error: {}").format(error_msg)

        except urllib3.exceptions.HTTPError as errh:
            error_msg = "HTTPError: {}".format(errh)
            system_tracking_logger.error("Error: {}").format(error_msg)
        except urllib3.exceptions.ConnectionError as errc:
            error_msg = "ConnectionError: {}".format(errc)
            system_tracking_logger.error("Error: {}").format(error_msg)
        except urllib3.exceptions.TimeoutError as errt:
            error_msg = "Timeout: {}".format(errt)
            system_tracking_logger.error("Error: {}").format(error_msg)
        except urllib3.exceptions.RequestError as err:
            error_msg = "RequestException: {}".format(err)
            system_tracking_logger.error("Error: {}").format(error_msg)
    
    def _urljoin(*args):
        trailing_slash = '/' if args[-1].endswith('/') else ''
        return '/'.join([str(x).strip('/') for x in args]) + trailing_slash
    
    def _vlookup(url, headers, vault_key, kv_v2):
        try:
            json_obj = {}
            
            retries  = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout  = Timeout(connect=2.0, read=7.0)
            http     = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)
            response = http.request(method='GET', url=url, headers=headers)  

            _display.v("Lookup Status: {0}".format(response.status))
            
            if (response.status == 200):
                data = response.data
                json_obj = json.loads(data)
               
                if kv_v2:
                    return [json_obj['data']['data'][vault_key]]
                else:
                    return [json_obj['data'][vault_key]]
            else:
                error_msg = "Response {0} on URL: {1}:{2}".format(response.status, url, vault_key)
                system_tracking_logger.error("Error: {}").format(error_msg)

        except urllib3.exceptions.HTTPError as errh:
            error_msg = "HTTPError: {}".format(errh)
            system_tracking_logger.error("Error: {}").format(error_msg)
        except urllib3.exceptions.ConnectionError as errc:
            error_msg = "ConnectionError: {}".format(errc)
            system_tracking_logger.error("Error: {}").format(error_msg)
        except urllib3.exceptions.TimeoutError as errt:
            error_msg = "Timeout: {}".format(errt)
            system_tracking_logger.error("Error: {}").format(error_msg)
        except urllib3.exceptions.RequestError as err:
            error_msg = "RequestException: {}".format(err)
            system_tracking_logger.error("Error: {}").format(error_msg)
    
    try:
        active_vault_instance = os.getenv('active_vault_instance')
    except:
        active_vault_instance = None
    if not active_vault_instance:
        module.fail_json(msg="active_vault_instance not set. Specify with ACTIVE_VAULT_INSTANCE environment variable")

    try:
        role_id = os.getenv('{0}_vault_roleid'.format(active_vault_instance))
    except:
        role_id = None
    if not role_id:
        module.fail_json(msg="{0}_vault_roleid not set. Specify with {0}_VAULT_ROLEID environment variable").format(active_vault_instance)

    try:
        secret_id = os.getenv('{0}_vault_secretid'.format(active_vault_instance))
    except:
        secret_id = None
    if not secret_id:
        module.fail_json(msg="{0}_vault_secretid not set. Specify with {0}_VAULT_SECRETID environment variable").format(active_vault_instance)
 
    try:
        vault_url = os.getenv('{0}_vault_url'.format(active_vault_instance))
    except:
        vault_url = None
    if not vault_url:
        module.fail_json(msg="{0}_vault_url not set. Specify with {0}_VAULT_URL environment variable").format(active_vault_instance)

    try:
        namespace = 'wineng'
    except:
        namespace = None
    if not namespace:
        module.fail_json(msg="namespace not set")
    
    try:
        login_url = _urljoin(vault_url, 'v1', namespace, 'auth/approle/login')
        encoded_body = json.dumps({
                "role_id": '{}'.format(role_id),
                "secret_id": '{}'.format(secret_id)
        })
        client_token = _get_auth_token(login_url, encoded_body)
    except:
        client_token = None
    if not client_token:
        module.fail_json(msg="client_token not set")
        
    # ----------------------
    # PARAMETERS
    # ----------------------

    credential_details = module.params.get('credential_details')
    organization       = module.params.get('organization')
    tower_prefix       = module.params.get('tower_prefix')
    tower_host         = module.params.get('tower_host')

    credential_fields = {}
    credential_fields['organization'] = module.resolve_name_to_id('organizations', organization)

    # ----------------------
    # START
    # ----------------------
    
    # configure credential_name
    if 'name' in credential_details:
        credential_name = tower_prefix + '_' + credential_details['name']
        credential_fields['name'] = credential_name
    else:
        module.fail_json(msg="name parameter not passed in within dict 'credential_details'")

    # configure credential_description
    if 'description' in credential_details:
        credential_description = credential_details['description'] + ' - ' + 'Modified: ' + str(datetime.datetime.now())
        credential_fields['description']  = credential_description
    else:
        module.fail_json(msg="description parameter not passed in within dict 'credential_details'")

    # configure credential_type
    if 'type' in credential_details:

        settings_detail = module.get_endpoint(endpoint='/')
        
        if 'tower_type' in settings_detail:
            if settings_detail['tower_type'] == 'Red Hat Ansible Automation Platform':
                if 'awx' in credential_details['type']:
                    cred_type = credential_details['type']['awx']  
                else:
                    cred_type = credential_details['type']
            elif settings_detail['tower_type'] == 'Red Hat Ansible Tower':
                if 'legacy' in credential_details['type']:
                    cred_type = credential_details['type']['legacy']
                else:
                    cred_type = credential_details['type']
            else:
                module.fail_json(msg="Unable to determine Ansible Tower Edition")
        else:
            module.fail_json(msg="Unable to determine Ansible Tower Edition")

        credential_type = module.get_one(endpoint='credential_types', name_or_id=cred_type, data={})

        if credential_type:
            credential_fields['credential_type'] = credential_type['id']
        else:
            module.fail_json(msg="Failed to get credential type, see response for details")
    else:
        module.fail_json(msg="type parameter not passed in within dict 'credential_details'")
    
    # configure inputs - json format
    if 'lookup' in credential_details:
        input_data = {}
        if credential_details['lookup']['type'] == 'hashi_vault':
            for vault_key in credential_details['lookup']['keys']:
              
                # Use vault session token
                query_url = _urljoin(vault_url, 'v1', credential_details['lookup']['path'])
                headers   = { "X-Vault-Token": '{}'.format(client_token),
                              "X-Vault-Namespace": '{}'.format(namespace),
                              "accept": "*/*" }
                v = _vlookup(query_url, headers, vault_key, True)
                input_data[vault_key] = str(v[0])

        credential_fields['inputs'] = input_data
    else:
        module.fail_json(msg="lookup parameter not passed in within dict 'credential_details'")

    # Get credential details
    endpoints  = module.get_endpoint(endpoint='/')
    credential = module.get_one(endpoint='credentials', name_or_id=credential_name, data={'organization': credential_fields['organization']})

    # Check Values
    for element in credential_fields:
        if element is None:
            module.fail_json(msg='{0} param in credential_fields dict not passed into the module. Unable to continue.'.format(element))

    # Create / Update credential
    if credential:
        # Perform an update to existing credential
        result = module.make_request(method='PUT', endpoint=credential['url'],**{'data': credential_fields})

        if result['status_code'] != 200:        
            module.fail_json(msg="Failed to update credential, see response for details", response=result)
    else:
        # Create new credential
        result = module.post_endpoint(endpoints['json']['credentials'],**{'data': credential_fields})

        if result['status_code'] != 201:        
            module.fail_json(msg="Failed to create credential, see response for details", response=result)

        credential = module.get_one(endpoint='credentials', name_or_id=credential_name, data={'organization': credential_fields['organization']})

    module.json_output['changed'] = True
    module.json_output['credential_name'] = credential_name
    module.json_output['credential_description'] = credential_description

    module.exit_json(**module.json_output)

if __name__ == '__main__':
    main()
