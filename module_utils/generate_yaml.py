from __future__ import absolute_import, division, print_function
__metaclass__ = type

import sys
import os
import re
import json

from typing import List, Dict, Tuple, Any
from .generators import ansible_cis, ansible_stig
from .xccdfoval_parser import XccdfOvalParser

sys.path.append(os.path.abspath(os.getcwd()))

def generate_yaml(input_path: str, output_dir: str, generator_type: str, filter_type: str = 'xccdf.xml') -> Dict[str, Any]:
    result = {'failure': [], 'successful': [], 'baselines': {}}
    xccdf_files, input_dir = get_xccdf_files(input_path, filter_type)

    for xccdf_file in xccdf_files:
        try:
            xfile_path, ofile_path, baseline, file_version = process_file_paths(input_dir, xccdf_file)
            if not os.path.exists(ofile_path):
                raise FileNotFoundError(f"OVAL file not found: {ofile_path}")

            print(f'\nProcessing xccdf file: {xfile_path}')
            print(f'Processing oval file: {ofile_path}')
            print(f'\nbaseline: {baseline}')
            print(f'file_version: {file_version}')

            output_path = os.path.join(output_dir, baseline)
            res = run(xfile_path, ofile_path, output_path, generator_type, file_version, baseline)

            update_result(result, baseline, file_version, res)
            result['successful'].append(xccdf_file)

        except Exception as e:
            print(f"Error processing {xccdf_file}: {e}")
            result['failure'].append(xccdf_file)
    
    print_result_summary(result)
    return result

def get_xccdf_files(input_path: str, filter_type: str) -> Tuple[List[str], str]:
    if os.path.isdir(input_path):
        return list_files(input_path, filter_type), input_path
    elif input_path.endswith('xccdf.xml'):
        return [os.path.basename(input_path)], os.path.dirname(input_path)
    else:
        raise ValueError('Filename does not contain an xml extension. Please ensure the file type is correct and passed into the path')

def process_file_paths(input_path: str, xccdf_file: str) -> Tuple[str, str, str, str]:
    xfile_path = os.path.join(input_path, xccdf_file)
    ofile_path = os.path.join(input_path, xccdf_file.replace('xccdf.xml', 'oval.xml'))
    match = re.search(r'^(.*)_v(\d+\.?\d+\.?\d*)', xccdf_file)
    if not match:
        raise ValueError(f"Unable to extract baseline and version from filename: {xccdf_file}")
    
    return xfile_path, ofile_path, match.group(1).lower(), match.group(2)

def update_result(result: Dict[str, Any], baseline: str, file_version: str, res: Dict[str, Any]) -> None:
    # Create a combined key for baseline and file version
    combined_key = f"{baseline}_{file_version}"
    
    # Ensure 'baselines' key exists in result
    if 'baselines' not in result:
        result['baselines'] = {}
    
    # Create a new dictionary for this baseline and file version
    baseline_data = {
        'baseline': baseline,
        'file_version': file_version,
        'profile_count': res.get('profile_count', 0),
        'group_count': res.get('group_count', 0),
        'rule_count': res.get('rule_count', 0)
    }
    
    # Add the baseline data to the result
    result['baselines'][combined_key] = baseline_data

def print_result_summary(result: Dict[str, Any]) -> None:
    if result['failure']:
        print('Failed to process the following input files:')
        print('  ' + '\n  '.join(result['failure']))
    else:
        print('\nFinished successfully!')

def run(xfile_path: str, ofile_path: str, output_path: str, generator_type: str, file_version: str, baseline: str) -> Dict[str, Any]:
    parser = XccdfOvalParser()
    oval_map = parser.parse_oval(ofile_path)
    xccdf_data = parser.parse_xccdf(xfile_path)

    if 'ansible_cis' in generator_type:
        return ansible_cis.ansible_cis_generate(xccdf_data, oval_map, output_path, file_version, baseline)
    elif 'ansible_stig' in generator_type:
        return ansible_stig.ansible_stig_generate(xccdf_data, oval_map, output_path, file_version, baseline)

def list_files(dir: str, regex: str) -> List[str]:
    return [filename for filename in os.listdir(dir) if re.search(regex, filename)]
