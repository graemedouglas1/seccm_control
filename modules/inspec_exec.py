
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
module: inspec_exec
author: GCS SecCM (Security Config Management) Team - State Street Corporation
short_description: Execute inspec on Node from Ansible Tower
description:
    See documentation for further information:
    - https://docs.chef.io/inspec/cli/
'''

import json
import os
import re
import logging

from subprocess import Popen, PIPE
from ..module_utils.tower_api import TowerAPIModule

system_tracking_logger = logging.getLogger('ssc.modules.inspec_exec')

def main():
    # Any additional arguments that are not fields of the item can be added here
    argument_spec = dict(
        profile_path=dict(required=True),
        host=dict(required=True),
        reporter=dict(required=True),
        backend=dict(required=True),
        port=dict(required=True),
        username=dict(required=False, default=None),
        password=dict(required=False, default=None, no_log=True),
        key_files=dict(required=False, default=None, no_log=True)
    )
   
    # Create a module for ourselves
    module = TowerAPIModule(argument_spec=argument_spec)

    # ----------------------
    # PARAMETERS
    # ----------------------
    
    profile_path = module.params.get('profile_path')
    host         = module.params.get('host')
    reporter     = module.params.get('reporter')
    backend      = module.params.get('backend')
    port         = module.params.get('port')
    username     = module.params.get('username')
    password     = module.params.get('password')
    key_files    = module.params.get('key_files')

    # ----------------------
    # START
    # ----------------------

    passed_checks   = []
    failed_checks   = []
    json_data       = {}
    result_controls = []
  
    # Get output file Path
    if ':' in reporter:
        output_path = reporter.split(':')[1]
    else:
        output_path = None

    if 'winrm' in backend:
        system_tracking_logger.error("Running over WinRM")
        cmd = "/usr/bin/inspec exec {0} -b '{1}' --host='{2}' --reporter='{3}' --user='{4}' --password='{5}' --port='{6}' --self-signed --ssl".format(profile_path, backend, host, reporter, username, password, port)
    elif 'ssh' in backend:
        cmd = "/usr/bin/inspec exec {0} -b '{1}' --host='{2}' --reporter='{3}' --key-files='{4}'".format(profile_path, backend, host, reporter, key_files)
    else:
        error_msg = "The provided backend type was not valid ({0}). Valid options are: [winrm|ssh].".format(backend)
        system_tracking_logger.error("Error: {}").format(error_msg)

    # Execute InSpec Command
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()

    # Gather Return Code
    while p.returncode not in [0, 100, 101]:
        module.json_output['failed'] = True
        module.json_output['returncode'] = p.returncode
    else:
        module.json_output['changed'] = True
        module.json_output['returncode'] = p.returncode

    # Read Json Report
    if output_path is not None:
        if os.path.isfile(output_path):
            if os.stat(output_path).st_size > 0:
                with open(output_path) as fd:
                    json_data = json.load(fd)
            else:
                error_msg = "The provided reporter file is empty ({0}).".format(output_path)
                system_tracking_logger.error("Error: {}").format(error_msg)

        # Gather results
        if any(json_data) and 'controls' in json_data:
            for item in json_data['controls']:
                result_controls = item
                control_id = item['id']
                if 'passed' in item['status']:
                    passed_checks.append("{0} : {1}".format(control_id, item['code_desc']))
                elif 'failed' in item['status']:
                    failed_checks.append("{0} : {1}".format(control_id, item['code_desc']))

            module.json_output['passed_checks'] = passed_checks
            module.json_output['failed_checks'] = failed_checks
            module.json_output['passed_count']  = len(passed_checks)
            module.json_output['failed_count']  = len(failed_checks)
            module.json_output['result']        = result_controls

        else:
            module.json_output['returncode']    = -1
            module.json_output['result']        = 'Unable to pull down controls from json file'

    module.exit_json(**module.json_output)

if __name__ == '__main__':
    main()
