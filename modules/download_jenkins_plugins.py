
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
module: download_jenkins_plugins
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Download Latest Jenkins Plugins for Node based on existing plugins Dir / Mandatory List
description:
    See documentation for further information:
    - https://updates.jenkins.io/
'''

import json
import requests
import urllib3
import shutil
import os
import re
import logging

from urllib3.util import Timeout, Retry
from typing import Iterable
from ..module_utils.tower_api import TowerAPIModule

system_tracking_logger = logging.getLogger('ssc.modules.download_jenkins_plugins')

def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        plugins=dict(required=True, type='list'),
        proxy=dict(required=True, default=None),
        plugin_dir=dict(required=True),
        jenkins_version=dict(required=True)
    )
   
    # Create a module for ourselves
    module = TowerAPIModule(argument_spec=argument_spec)
    
    # ----------------------
    # PARAMETERS
    # ----------------------
    
    plugins           = module.params.get('plugins')
    proxy             = module.params.get('proxy')
    plugin_dir        = module.params.get('plugin_dir')
    jenkins_version   = module.params.get('jenkins_version')


    # ----------------------
    # FUNCTIONS
    # ----------------------

    def query_api(uri, method, headers, proxy=None, input_data=None, filename=None):
        try:
            json_obj = {}
                
            retries  = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout  = Timeout(connect=2.0, read=7.0)
            
            if not str(proxy):
              http = urllib3.ProxyManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout, proxy_url=proxy)
            else:
              http = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)
            
            if method == 'GET':
                if filename:
                    with open(filename, 'wb') as out:
                        response = http.request(method=method, url=uri, redirect=True, preload_content=False)
                        shutil.copyfileobj(response, out)
                else:
                    response = http.request(method=method, url=uri, redirect=True, headers=headers)
                     
                if (response.status == 200):
                    return response.data
                else:
                    print('Response {0} on URL: {1}:{2}'.format(response.status, uri))
    
            elif method == 'POST':
                response = http.request(method='POST', url=uri, headers=headers, body=input_data)
               
                if (response.status == 201):
                    return response
                else:
                    print('Response {0} on URL: {1}, Data: {2}'.format(response.status, uri, response.data))
                        
        except urllib3.exceptions.HTTPError as errh:
            error_msg = "HTTPError: {}".format(errh)
            system_tracking_logger.error("Error: {}".format(error_msg))
        except urllib3.exceptions.ConnectionError as errc:
            error_msg = "ConnectionError: {}".format(errc)
            system_tracking_logger.error("Error: {}".format(error_msg))
        except urllib3.exceptions.TimeoutError as errt:
            error_msg = "Timeout: {}".format(errt)
            system_tracking_logger.error("Error: {}".format(error_msg))
        except urllib3.exceptions.RequestError as err:
            error_msg = "RequestException: {}".format(err)
            system_tracking_logger.error("Error: {}".format(error_msg))
    
    def dependson(item):
        r = []
        if 'dependencies' in updcenter_json['plugins'][item] and updcenter_json['plugins'][item]['dependencies'] is not None:
            if isinstance(updcenter_json['plugins'][item]['dependencies'], Iterable):
                for p in updcenter_json['plugins'][item]['dependencies']:
                    r.append(p['name'])
            else:
                r.append(updcenter_json['plugins'][item]['dependencies']['name'])
        return r
    
    def get_plugin(item):
        if not item in expanded_plugins:
            expanded_plugins.append(item)
            for m in dependson(item):
                get_plugin(m)
            in_scope_plugins.append(item)
  
    # ----------------------
    # START
    # ----------------------

    expanded_plugins = []
    in_scope_plugins = []
    plugin_versons   = {}
 
    # Download update-center.json
    updcenter      = (query_api(uri="https://updates.jenkins.io/dynamic-stable-{0}/update-center.json".format(jenkins_version), method='GET', headers={'accept': 'application/json'}, proxy=proxy)).decode(encoding="utf-8")
    updcenter_data = updcenter.replace('updateCenter.post(', '').replace(');', '')
    updcenter_json = json.loads(updcenter_data)

    # Download plugin-versions.json
    pluginver = query_api(uri="https://updates.jenkins.io/current/plugin-versions.json", method='GET', headers={'accept': 'application/json'}, proxy=proxy)  
    pluginver_json = json.loads(pluginver)
    
    for item in plugins:
        get_plugin(item)

    for plugin in in_scope_plugins:
        
        filename = "{0}{1}".format(plugin_dir, os.path.basename(updcenter_json['plugins'][plugin]['url']))
        
        print('Downloading file: {0}'.format(filename))
        
        response = query_api(uri=updcenter_json['plugins'][plugin]['url'], method='GET', headers=None, proxy=proxy, filename="{0}".format(filename))
        
        plugin_versons[plugin] = {}
        plugin_versons[plugin]['name']     = updcenter_json['plugins'][plugin]['name']
        plugin_versons[plugin]['version']  = updcenter_json['plugins'][plugin]['version']
        plugin_versons[plugin]['url']      = updcenter_json['plugins'][plugin]['url']
    
    module.json_output['changed']         = True
    module.json_output['plugins']         = plugins
    module.json_output['plugin_dir']      = plugin_dir
    module.json_output['jenkins_version'] = jenkins_version
    module.json_output['result']          = plugin_versons

    module.exit_json(**module.json_output)            

if __name__ == '__main__':
    main()
