#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, re, urllib3

from ansible.errors import AnsibleError, AnsibleParserError, AnsibleLookupError
from urllib3.util import Timeout, Retry
from ansible.utils.display import Display

try:
    import json
except ImportError:
    import simplejson as json

_display = Display()

# Query API
def query_api(api_url, api_token):
    try:
        json_obj = {}
        api_data = {}   
        headers  = { "x-api-key": '{}'.format(api_token),
                     "Content-Type": 'application/json' }

        retries = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
        timeout = Timeout(connect=2.0, read=7.0)
        http = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)

        response = http.request(method='GET', url=api_url, headers=headers)            
        _display.v("HTTP Status: {0}".format(response.status))
        
        if (response.status == 200):            
            data = response.data
            json_obj = json.loads(data.decode('utf-8'))

            if 'result' in json_obj and json_obj['result'] is not None:
                if 'exceptionData' in json_obj['result'] and json_obj['result']['exceptionData'] is not None:
                    return json_obj['result']['exceptionData']  
                else:
                    return api_data
            else:
                return api_data
        else:
            api_data
               
    # return empty value if error during request
    except urllib3.exceptions.HTTPError as errh:
         raise AnsibleError('HTTPError: %s' % (errh))
    except urllib3.exceptions.ConnectionError as errc:
        raise AnsibleError('ConnectionError: %s' % (errc))
    except urllib3.exceptions.TimeoutError as errt:
        raise AnsibleError('Timeout: %s' % (errt))
    except urllib3.exceptions.RequestError as err:
        raise AnsibleError('RequestException: %s' % (err))

# Get CIS role
def get_cisrole(role):
    if role == 'master_image':
        return 'master'
    elif role == 'domain_controller':
        return 'dc'
    else:
        return 'member'

# Get Environment
def get_environment(env_switch):
    if 'SSC_TOWER_URL' in os.environ:
        tower_host = str(os.environ.get('SSC_TOWER_URL')).lower()
    else:
        raise AnsibleLookupError('Unable to retrieve tower_host Environment')

    if env_switch == 'towerEnvironment':
        if 'lab' in tower_host:
            return 'lab'
        elif 'dev' in tower_host:
            return 'dev'
        elif 'uat' in tower_host:
            return 'uat'
        elif 'prd' in tower_host:
            return 'prod'
        elif 'vm-tws' in tower_host:
            return 'azlab'
        else:
            return 'azlab'
    
    elif env_switch == 'snowEnvironment':
        if 'lab' in tower_host:
            return 'DEVELOPMENT'
        elif 'dev' in tower_host:
            return 'DEVELOPMENT'
        elif 'uat' in tower_host:
            return 'UAT'
        elif 'prd' in tower_host:
            return 'PRODUCTION'
        elif 'vm-tws' in tower_host:
            return 'DEVELOPMENT'
        else:
            return 'DEVELOPMENT'
    else:
        raise AnsibleLookupError('Incorrect Parameter Passed into env_switch')
