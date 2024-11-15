
#!/usr/bin/python
# coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.generate_yaml import *

def main():
    # Any additional arguments that are not fields of the item can be added here
    module = AnsibleModule(
        argument_spec = dict(
            generator_type=dict(required=True),
            input_dir=dict(required=True),
            output_dir=dict(required=True),
            input_file=dict(required=False, default=None)
        )
    )

    # ----------------------
    # PARAMETERS
    # ----------------------

    generator_type = module.params.get('generator_type')
    input_dir      = module.params.get('input_dir')
    input_file     = module.params.get('input_file')
    output_dir     = module.params.get('output_dir')

    # ----------------------
    # START
    # ----------------------

    if input_file:
        input_dir = os.path.join(input_dir, input_file)
    result = generate_yaml(input_path=input_dir, output_dir=output_dir, generator_type=generator_type)

    json_output = {}
    json_output['input_dir']  = input_dir
    json_output['output_dir'] = output_dir
    json_output['result']     = result

    if 'failure' in result and len(result['failure']) > 0:
        json_output['failed'] = True
    else:
        json_output['changed'] = True

    module.exit_json(**json_output)

if __name__ == '__main__':
    main()