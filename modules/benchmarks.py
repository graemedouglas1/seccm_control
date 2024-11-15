
#!/usr/bin/python
# coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module_utils.generate_yaml import *

generator_type = 'ansible_cis'
input_dir = '../../gcs_scm_benchmarks/files/benchmarks'
#input_file = 'CIS_Microsoft_Windows_Server_2008_Benchmark_v3.1.0-xccdf.xml'
input_file = None
output_dir = '../results'

if input_file:
    input_dir = os.path.join(input_dir, input_file)

result = generate_yaml(input_path=input_dir, output_dir=output_dir, generator_type=generator_type)

json_output = {}
json_output['input_dir']  = input_dir
json_output['output_dir'] = output_dir
json_output['result']     = result

#print(json_output)