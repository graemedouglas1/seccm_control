import re
import os
import json
import xml.etree.ElementTree as ET

from pathlib import Path
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader(os.path.abspath(os.path.join(os.getcwd(), '..', 'templates'))))

def ansible_cis_generate(xccdf_data, oval_map, output_path, file_version, baseline):
  rule_set = get_tagged_rule_ids(xccdf_data['profiles'], xccdf_data['profile_result'])
  
  if len(rule_set) > 0:

    # Create Version folder
    out_dir = os.path.join(output_path, file_version)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    
    # Write all.txt
    with open(os.path.join(output_path, file_version, 'all.txt'), 'w', encoding='utf-8') as file:
        file.write('\n'.join(xccdf_data['rule_list']))

    for rs in rule_set:
        out_dir = os.path.join(output_path, file_version, f'{rs["suffix"] or ""}')
        render_rule_set(xccdf_data, oval_map, rs['rules'], baseline, out_dir, 'common.yml')

    xccdf_data['errors_found'] = False
  else:
    xccdf_data['errors_found'] = True

  return xccdf_data

def map_users_to_sids(users):
    # Mapping dictionary for user names to their corresponding SID
    user_to_sid = {
        'Administrators': 'S-1-5-32-544',
        'Users': 'S-1-5-32-545',
        'Guests': 'S-1-5-32-546',
        'Authenticated Users': 'S-1-5-11',
        'Everyone': 'S-1-1-0',
        'Creator Owner': 'S-1-3-0',
        'Creator Group': 'S-1-3-1',
        'System': 'S-1-5-18',
        'LOCAL SERVICE': 'S-1-5-19',
        'NETWORK SERVICE': 'S-1-5-20',
        'Enterprise Admins': 'S-1-5-32-519',
        'Domain Admins': 'S-1-5-32-512',
        'Domain Users': 'S-1-5-32-513',
        'Schema Admins': 'S-1-5-32-518',
        'IIS_IUSRS': 'S-1-5-32-569',
        'SERVICE': 'S-1-5-6',
        'Remote Desktop Users': 'S-1-5-32-555'
    }

    # Map users to their SID or return the user as is if not in the mapping
    return [user_to_sid.get(user.strip().replace('(Deny) ',''), user.strip()) for user in users]

def extract_iis_tasks(oval_tests, rule):
    iis_tasks = []
    if not oval_tests or not isinstance(oval_tests[0], list):
        return iis_tasks
    
    for test in oval_tests[0]:
        if isinstance(test, dict) and test.get('test_type') == 'bindings_test':
            iis_config = "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"
            match = next((v['#text'] for k, v in test['object_elements'].items() if k == 'site_name' and isinstance(v, dict) and '#text' in v), '')
            

def extract_account_status(oval_tests, rule):
    accounts = []
    if not oval_tests or not isinstance(oval_tests[0], list):
        return accounts

    for test in oval_tests[0]:
        if isinstance(test, dict) and test.get('test_type') == 'user_sid55_test' or isinstance(test, dict) and test.get('test_type') == 'sid_sid_test' and 'Accounts: Rename' not in rule.get('title',''):
            # Extract the SID pattern from object_elements -> user_sid
            user_sid_pattern = next((v['#text'] for k, v in test['object_elements'].items() if k == 'user_sid' and isinstance(v, dict) and '#text' in v), '')
            if not user_sid_pattern or user_sid_pattern == '':
                user_sid_pattern = next((v['#text'] for k, v in test['object_elements'].items() if k == 'trustee_sid' and isinstance(v, dict) and '#text' in v), '')

            # Extract the 'enabled' status from the state_elements -> enabled
            enabled_status = next((v['#text'] for k, v in test['state_elements'].items() if k == 'enabled' and isinstance(v, dict) and '#text' in v), '0')
            
            # Map the enabled status to a more readable format (0 = disabled, 1 = enabled)
            rule = 'should_be enabled' if enabled_status == '1' else 'should_be disabled'
            
            # Extract the check existence rule (default to 'should_exist' if not found)
            should_exist = next((v['#text'] for k, v in test['test_elements'].items() if k == '@check_existence' and isinstance(v, dict) and '#text' in v), 'should_exist')
            if should_exist == 'at_least_one_exists':
                should_exist = 'should exist'
            elif should_exist == 'none_exist':
                should_exist = 'should_not exist'

            # Create two separate entries for the same user: one for 'should_be' and one for 'should_exist'
            accounts.append({'user': user_sid_pattern, 'rule': rule})
            accounts.append({'user': user_sid_pattern, 'rule': should_exist})

        elif isinstance(test, dict) and test.get('test_type') == 'user_test':
            # Extract the user name from object_elements -> user
            user_name = next((v['#text'] for k, v in test['object_elements'].items() if k == 'user' and isinstance(v, dict) and '#text' in v), '')

            # Extract the 'test_check_existence' status (default to 'should_exist' if not found)
            check_existence = test.get('test_check_existence', 'none_exist')
            if check_existence == 'none_exist':
                should_exist = 'should_not exist'
            elif check_existence == 'at_least_one_exists':
                should_exist = 'should exist'

            # Add user-based account status entries
            if user_name:
                accounts.append({'user': user_name, 'rule': should_exist})

        elif isinstance(test, dict) and 'Accounts: Rename' in rule.get('title',''):
            # Extract the user name from object_elements -> user
            user_name = next((v['#text'] for k, v in test['state_elements'].items() if k == 'trustee_name' and isinstance(v, dict) and '#text' in v), '')

            # Extract the 'test_check_existence' status (default to 'should_exist' if not found)
            check_existence = test.get('test_check_existence', 'none_exist')
            should_exist = 'should_not exist'

            # Add user-based account status entries
            if user_name:
                accounts.append({'user': user_name, 'rule': should_exist})


    return accounts

def map_title_to_right(title):
    cis_to_user_rights = {
        "Account lockout duration": "SeDenyInteractiveLogonRight",
        "Audit policy change": "SeAuditPrivilege",
        "Backup files and directories": "SeBackupPrivilege",
        "Change the system time": "SeSystemTimePrivilege",
        "Create a pagefile": "SeCreatePagefilePrivilege",
        "Shutdown the system": "SeShutdownPrivilege",
        "Add workstations to domain": "SeRemoteInteractiveLogonRight",
        "Allow logon locally": "SeInteractiveLogonRight",
        "Allow logon through Remote Desktop Services": "SeRemoteInteractiveLogonRight",
        "Change the time zone": "SeTimeZonePrivilege",
        "Debug programs": "SeDebugPrivilege",
        "Force shutdown from a remote system": "SeRemoteShutdownPrivilege",
        "Impersonate a client after authentication": "SeImpersonatePrivilege",
        "Increase scheduling priority": "SeIncreaseSchedulingPriorityPrivilege",
        "Increase a process working set": "SeIncreaseWorkingSetPrivilege",
        "Log on as a batch job": "SeBatchLogonRight",
        "Log on as a service": "SeServiceLogonRight",
        "Log on locally": "SeInteractiveLogonRight",
        "Modify firmware environment values": "SeSystemEnvironmentPrivilege",
        "Restore files and directories": "SeRestorePrivilege",
        "Shut down the system": "SeShutdownPrivilege",
        "Take ownership of files or other objects": "SeTakeOwnershipPrivilege",
        "Access this computer from the network": "SeNetworkLogonRight",
        "Log on as a domain user": "SeNetworkLogonRight",
        "Log on as a remote interactive user": "SeRemoteInteractiveLogonRight",
        "Log on as a guest": "SeGuestLogonRight",
        "Deny log on as a batch job": "SeDenyBatchLogonRight",
        "Deny log on as a service": "SeDenyServiceLogonRight",
        "Deny log on locally": "SeDenyInteractiveLogonRight",
        "Deny log on through Remote Desktop Services": "SeDenyRemoteInteractiveLogonRight",
        "Deny access to this computer from the network": "SeDenyNetworkLogonRight",
        "Deny log on as a guest": "SeDenyGuestLogonRight",
        "Deny log on as a domain user": "SeDenyNetworkLogonRight",
        "Enable computer and user accounts to be trusted for delegation": "SeEnableDelegationRight",
        "Back up files and directories": "SeBackupPrivilege",
        "Change system time": "SeSystemTimePrivilege",
        "Create a pagefile": "SeCreatePagefilePrivilege",
        "Debug programs": "SeDebugPrivilege",
        "Force shutdown from a remote system": "SeRemoteShutdownPrivilege",
        "Impersonate a client after authentication": "SeImpersonatePrivilege",
        "Increase scheduling priority": "SeIncreaseSchedulingPriorityPrivilege",
        "Increase a process working set": "SeIncreaseWorkingSetPrivilege",
        "Log on as a batch job": "SeBatchLogonRight",
        "Log on as a service": "SeServiceLogonRight",
        "Log on locally": "SeInteractiveLogonRight",
        "Modify firmware environment values": "SeSystemEnvironmentPrivilege",
        "Restore files and directories": "SeRestorePrivilege",
        "Shut down the system": "SeShutdownPrivilege",
        "Take ownership of files or other objects": "SeTakeOwnershipPrivilege",
        "Access this computer from the network": "SeNetworkLogonRight",
        "Allow log on locally": "SeInteractiveLogonRight",
        "Allow log on through Remote Desktop Services": "SeRemoteInteractiveLogonRight",
        "Log on as a batch job": "SeBatchLogonRight",
        "Log on as a service": "SeServiceLogonRight",
        "Log on as a domain user": "SeNetworkLogonRight",
        "Log on as a remote interactive user": "SeRemoteInteractiveLogonRight",
        "Log on as a guest": "SeGuestLogonRight",
        "Deny log on as a batch job": "SeDenyBatchLogonRight",
        "Deny log on as a service": "SeDenyServiceLogonRight",
        "Deny log on locally": "SeDenyInteractiveLogonRight",
        "Deny log on through Remote Desktop Services": "SeDenyRemoteInteractiveLogonRight",
        "Deny access to this computer from the network": "SeDenyNetworkLogonRight",
        "Deny log on as a guest": "SeDenyGuestLogonRight",
        "Deny log on as a domain user": "SeDenyNetworkLogonRight",
        "Allow logon as a batch job": "SeBatchLogonRight",
        "Allow logon as a service": "SeServiceLogonRight",
        "Allow logon locally": "SeInteractiveLogonRight",
        "Access this computer from the network": "SeNetworkLogonRight",
        "Change the time zone": "SeTimeZonePrivilege",
        "Backup files and directories": "SeBackupPrivilege",
        "Restore files and directories": "SeRestorePrivilege",
        "Modify firmware environment values": "SeSystemEnvironmentPrivilege",
        "Take ownership of files or other objects": "SeTakeOwnershipPrivilege",
        "Shut down the system": "SeShutdownPrivilege",
        "Force shutdown from a remote system": "SeRemoteShutdownPrivilege",
        "Debug programs": "SeDebugPrivilege",
        "Create a pagefile": "SeCreatePagefilePrivilege",
        "Shutdown the system": "SeShutdownPrivilege",
        "Impersonate a client after authentication": "SeImpersonatePrivilege",
        "Enable computer and user accounts to be trusted for delegation": "SeEnableDelegationRight",
        "Generate security audits": "SeAuditPrivilege",
        "Modify firmware environment values": "SeSystemEnvironmentPrivilege",
        "Load and unload device drivers": "SeLoadDriverPrivilege",
        "Lock pages in memory": "SeLockMemoryPrivilege",
        "Manage auditing and security log": "SeSecurityPrivilege",
        "Modify an object label": "SeRelabelPrivilege",
        "Perform volume maintenance tasks": "SeManageVolumePrivilege",
        "Profile single process": "SeProfileSingleProcessPrivilege",
        "Profile system performance": "SeSystemProfilePrivilege",
        "Replace a process level token": "SeAssignPrimaryTokenPrivilege",
        "Create symbolic links": "SeCreateSymbolicLinkPrivilege",
        "Create permanent shared objects": "SeCreatePermanentSharedObjectPrivilege",
        "Create a token object": "SeCreateTokenPrivilege",
        "Create global objects": "SeCreateGlobalPrivilege",
        "Act as part of the operating system": "SeTcbPrivilege",
        "Adjust memory quotas": "SeIncreaseQuotaPrivilege",
        "Access credential manager as a trusted caller": "SeTrustedCredManAccessPrivilege",
    }

    cleaned_title = re.sub(r'\(L\d\)\s*Ensure\s*', '', title).strip()
    
    cleaned_title = cleaned_title.lower()
    for rule, user_right in cis_to_user_rights.items():
        if rule.lower() in cleaned_title: 
            return user_right
    
    return None
    
def extract_user_rights(oval_tests, rule):
    user_rights = []
    if not oval_tests or not isinstance(oval_tests[0], list):
        return user_rights

    for test in oval_tests[0]:
        if isinstance(test, dict) and test.get('test_type') == 'userright_test' or isinstance(test, dict) and test.get('test_type') == 'sid_sid_test' and 'Accounts: Rename' not in rule.get('title',''):
            # Extract users list from state_elements
            users_str = next((v['#text'] for k, v in test['state_elements'].items() if isinstance(v, dict) and '#text' in v), '')
            users = [user.strip() for user in users_str.split(',')] if users_str else []

            # Use the helper function to map users to their corresponding SIDs
            users_with_sids = map_users_to_sids(users)
            rights_name = map_title_to_right(rule.get('title',''))
            
            # Extract rights_name based on object_comment (if available)
            # comment = test.get('object_comment', '')
            #if comment.startswith("Configure '") and comment.endswith("'"):
            #    rights_name = comment[11:-1]  # Only need the bit after 'Configure '
            #elif "Ensure 'Back up files and directories'" in rule.get('title',''):
            #    rights_name = 'SeBackupPrivilege'
            #else:
            #    match = re.search(r"'([^']*)'", comment)

 #               if match:
#                    rights_name = match.group(1)

            # Determine the "should_be" value based on the 'test_elements' section
            should_be = test.get('test_elements', {}).get('@check_existence', '')
            if should_be == 'at_least_one_exists' and '(Deny) ' not in users_str:
                should_be = f'should match_array {str(users_with_sids)}'
            elif should_be == 'at_least_one_exists' and '(Deny) ' in users_str:
                should_be = f'should_not match array {str(users_with_sids)}'
            elif should_be == 'none_exist':
                should_be = 'should be_empty'

            userright_info = {
                'rights_name': rights_name,
                'should_be': should_be  # Updated should_be to reflect both allowed and denied users
            }

            # Append the user right information
            user_rights.append(userright_info)

    return user_rights

def extract_wmi_tests(oval_tests):
    wmi_checks = []
    
    if not oval_tests or not isinstance(oval_tests[0], list):
        return wmi_checks
    
    for test in oval_tests[0]:
        if isinstance(test, dict) and test.get('test_type') == 'wmi57_test':
            # Extract the test_check_existence value
            test_check_existence = test.get('test_elements', {}).get('@check_existence', '')

            # Extract the #text value for the setting from state_elements
            state_elements = test.get('state_elements', {})
            setting_text = ''
            if state_elements:
                # Extract the field where the @name is 'setting' and get the #text value
                field = state_elements.get('result', {}).get('field', {})
                if field and field.get('@name') == 'setting':
                    setting_text = field.get('#text', '')

                    # Convert to '1' for True and '0' for False if needed
                    if setting_text == 'False':
                        setting_text = '0'
                    elif setting_text == 'True':
                        setting_text = '1'

            if test_check_existence == 'at_least_one_exists':
                should_be = 'should eq ' + setting_text
            elif test_check_existence == 'none_exist':
                should_be = 'should_not exist'

            object_elements = test.get('object_elements', {})
            if object_elements:
                match = re.search(r"KeyName='([^']+)'", object_elements.get('wql', {}).get('#text', ''))
                if match:
                  key_name = match.group(1)

            # If we found the relevant details, store them in wmi_checks
            if test_check_existence and setting_text:
                wmi_checks.append({
                    'name': key_name,
                    'should_be': should_be
                })
    
    return wmi_checks

def extract_registry_info(oval_tests, complex_checks):
    registry_checks = []
    
    if not oval_tests or not isinstance(oval_tests[0], list):
        return registry_checks

    for test in oval_tests[0]:
        if isinstance(test, dict) and test.get('test_type') == 'registry_test':
            entity_check = test.get('test_check_existence', '')
            object_elements = test.get('object_elements', {})
            object_variables = test.get('object_variables', {})

            if entity_check == 'none_exist':
                should_be_present = False
            else:
                should_be_present = True

            registry_hive = object_elements.get('hive', {}).get('#text', '')
            registry_path = object_elements.get('key', {}).get('#text', '')
            registry_value = object_elements.get('name', {}).get('#text', '')

            # Handle HKEY_USERS special case
            if registry_hive == 'HKEY_USERS':
                sid_pattern = registry_path
                if not sid_pattern and isinstance(object_elements.get('key'), dict):
                    sid_pattern = object_elements['key'].get('#text', '')
                
                # Get the additional path from object_variables
                additional_path = ''
                if 'key' in object_variables:
                    var_ref = object_variables['key'].get('@var_ref', {})
                    if isinstance(var_ref, dict):
                        var_elements = var_ref.get('var_elements', {})
                        concat = var_elements.get('concat', {})
                        if isinstance(concat, dict):
                            literal_component = concat.get('literal_component', {})
                            if isinstance(literal_component, dict):
                                additional_path = literal_component.get('#text', '')
                
                registry_path = f"{sid_pattern}{additional_path}"

            registry_info = {
                'registry_hive': registry_hive,
                'registry_path': registry_path,
                'registry_value': registry_value,
                'should_be_present': should_be_present
            }

            # Check for the pattern match condition in the state_elements
            state_elements = test.get('state_elements', {})
            if state_elements:
                value = state_elements.get('value', {})
                operation = value.get('@operation', '')
                check = value.get('#text','')

                # If no check is found in state_elements, use the check from complex_checks
                if not check and complex_checks:
                    for complex_check in complex_checks:
                        if 'value' in complex_check:
                            check = complex_check['value']
                            break 
                
                # Add a new property if the check type is 'pattern match'
                if operation == 'pattern match':
                    if entity_check and entity_check == 'none_exist':
                        registry_info['should_be'] = 'should_eq []'
                    elif entity_check and entity_check == 'at_least_one_exists':
                        registry_info['should_be'] = 'should cmp ' + check

            for check in complex_checks:
                if check.get('value','') in ['reg_dword', 'reg_sz', 'reg_qword', 'reg_binary', 'reg_expand_sz', 'reg_multi_sz']:
                    if check.get('value','') == 'reg_dword':
                        registry_info['registry_type'] = ':dword'
                    if check.get('value','') == 'reg_qword':
                        registry_info['registry_type'] = ':qword'
                    if check.get('value','') == 'reg_sz':
                        registry_info['registry_type'] = ':string'
                    if check.get('value','') == 'reg_multi_sz':
                        registry_info['registry_type'] = ':multi_string'
                    if check.get('value','') == 'reg_binary':
                        registry_info['registry_type'] = ':binary'
                    if check.get('value','') == 'reg_expand_sz':
                        registry_info['registry_type'] = ':expand_string'
                else:
                    registry_info['registry_data'] = check.get('value','')

            registry_checks.append(registry_info)

    return registry_checks

def extract_complex_checks(rule):
    complex_checks = []
    if not isinstance(rule, dict):
        return complex_checks

    complex_check = rule.get('complex_check')
    if not isinstance(complex_check, dict):
        return complex_checks

    checks = complex_check.get('checks')
    if not isinstance(checks, list):
        return complex_checks

    for check in checks:
        if not isinstance(check, dict):
            continue

        check_exports = check.get('check_export')
        if not isinstance(check_exports, list):
            continue

        for export in check_exports:
            if not isinstance(export, dict):
                continue

            value_id = export.get('value_id')
            if not value_id:
                continue

            values = rule.get('values', {})
            if not isinstance(values, dict):
                continue

            value = values.get(value_id)
            if not isinstance(value, dict):
                continue

            content_ref = check.get('content_ref', {})
            if not isinstance(content_ref, dict):
                content_ref = {}

            rule_check=''
            if value.get('type','') == 'number':
                if value.get('operator','') == 'greater than or equal':
                    rule_check = 'should be >= ' + value.get('value','')
                if value.get('operator','') == 'less than or equal':
                    rule_check = 'should be <= ' + value.get('value','')
                if value.get('operator','') == 'greater than':
                    rule_check = 'should be > ' + value.get('value','')
                if value.get('operator','') == 'less than':
                    rule_check = 'should be < ' + value.get('value','')
                if value.get('operator','') == 'equals':
                    rule_check = 'should eq ' + value.get('value','')
                if value.get('operator','') == 'not equal':
                    rule_check = 'should_not eq ' + value.get('value','')
            elif value.get('type','') == 'boolean':
                if value.get('operator') == 'equals':
                    rule_check = 'should eq ' + value.get('value','')
            elif value.get('type','') == 'string' and 'AUDIT' not in value.get('value',''):
                if value.get('operator') == 'equals':
                    rule_check = 'should cmp == ' + value.get('value','')
                elif value.get('operator','') == 'pattern match':
                    match = re.search(r"to '([^']+)'", value.get('title',''))
                    if match:
                        rule_check = 'should cmp ' + match.group(1)
            elif value.get('type','') == 'string' and 'AUDIT' in value.get('value',''):
                if value.get('value','') == 'AUDIT_SUCCESS_FAILURE':
                    rule_check = "should eq 'Success and Failure'"
                elif value.get('value','') == 'AUDIT_FAILURE':
                    rule_check = "should eq 'Failure'"
                elif value.get('value','') == 'AUDIT_SUCCESS':
                    rule_check = "should eq 'Success'"
            
            check_name=''
            if 'Password Hist Len' in value.get('title','') or "'Enforce password history'" in value.get('title',''):
                check_name = 'PasswordHistorySize'
            elif 'Max Passwd Age' in value.get('title','') or "'Maximum password age'" in value.get('title',''):
                check_name = 'MaximumPasswordAge'
            elif 'Min Passwd Age' in value.get('title','') or "'Minimum password age'" in value.get('title',''):
                check_name = 'MinimumPasswordAge'
            elif 'Min Passwd Len' in value.get('title','') or "'Minimum password length'" in value.get('title',''):
                check_name = 'MinimumPasswordLength'
            elif 'Password Complexity' in value.get('title','') or "'Password must meet complexity requirements'" in value.get('title',''):
                check_name = 'PasswordComplexity'
            elif 'Reversible Encryption' in value.get('title','') or "'Store passwords using reversible encryption'" in value.get('title',''):
                check_name = 'ClearTextPassword'
            elif 'Account lockout duration' in value.get('title',''):
                check_name = 'LockoutDuration'
            elif 'Account lockout threshold' in value.get('title',''):
                check_name = 'LockoutBadCount'
            elif 'Reset account lockout counter after' in value.get('title',''):
                check_name = 'ResetLockoutCount'
            elif 'AUDIT' in value.get('value',''):
                match = re.search(r"'([^']+)'", value.get('title',''))
                if match:
                    check_name = match.group(1).replace('_',' ').title()
            
            complex_checks.append({
                'title': value.get('title', ''),
                'operator': value.get('operator', ''),
                'type': value.get('type', ''),
                'value': value.get('value', ''),
                'matched': content_ref.get('name', ''),
                'rule_check': rule_check or 'Undefined',
                'check_name': check_name or 'Undefined'
            })

    return complex_checks

def render_rule_set(xccdf_data, oval_map, rule_elements, baseline, out_dir, file_path):
    filepath = os.path.join(out_dir, file_path)
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    manifest = []
    tasks = []

    for group in xccdf_data['groups']:
        for rule in group['rules']:
            tags = []
            
            # Check if rule_elements is a set
            if isinstance(rule_elements, set):
                if rule['id'] in rule_elements:
                    tags.append(baseline)  # or any other default tag you want to use
                    rule_name = re.sub(r'_', ' ', rule['id'].split(f'{rule["number"]}_')[1].strip())
                    tags.append(f'rule_{rule["number"]}')
                    tags.append(baseline)
                    
                    check_type=''
                    if group['title'] in ['Password Policy', 'Account Lockout Policy', 'User Rights Assignment', 'Accounts']:
                        check_type = 'security_policy'
                    
                    complex_checks = extract_complex_checks(rule)

                    desc = "".join(char for char in rule.get('description','') if char.isalnum() or char in [' ', '.', '/', '\\', ',','!','\n'])

                    remediation_advice = rule.get('fixtext','No remediation listed.')

                    # Initialize task with common elements
                    task = {
                        'name': rule_name,
                        'id': rule.get('id'),
                        'number': rule.get('number'),
                        'impact': rule.get('impact'),
                        'description': desc,
                        'cis_section': group['title'],
                        'tags': tags,
                        'enabled': 'true',
                        'complex_check': rule.get('complex_check'),
                        'complex_checks': complex_checks,
                        'check_type': check_type or 'Undefined',
                        'remediation_advice': remediation_advice
                    }

                    # Check if there's matching OVAL data
                    oval_match = next((oval_data for oval_id, oval_data in oval_map.items() 
                                       if rule['id'] == oval_data['xccdf_id']), None)
                    if oval_match:
                        task.update({
                            'oval_id': next(oval_id for oval_id, oval_data in oval_map.items() 
                                            if rule['id'] == oval_data['xccdf_id']),
                            'oval_description': oval_match['description'],
                            'oval_tests': oval_match['associated_tests'],
                        })

                        registry_checks = extract_registry_info(oval_match['associated_tests'], complex_checks)
                        if registry_checks:
                            if registry_checks[0]['registry_hive'] == 'HKEY_USERS':
                                base_path = None
                                for item in registry_checks:
                                    if base_path is None:
                                        base_path = item['registry_path']
                                    else:
                                        base_path += item['registry_path']
                                
                                merged_check = registry_checks[-1].copy()
                                merged_check['registry_path'] = base_path
                                task['registry_checks'] = [merged_check]
                            else:
                                task['registry_checks'] = registry_checks

                        user_rights = extract_user_rights(oval_match['associated_tests'], rule)
                        if user_rights:
                            task['user_rights'] = user_rights

                        account_status = extract_account_status(oval_match['associated_tests'], rule)
                        if account_status:
                            task['account_status'] = account_status

                        wmi_checks = extract_wmi_tests(oval_match['associated_tests'])
                        if wmi_checks:
                            task['wmi_checks'] = wmi_checks

                        if 'cis_microsoft_iis' in baseline:
                            iis_tasks = extract_iis_tasks(oval_match['associated_tests'], rule)
                            if iis_tasks:
                                task['iis_tasks'] = iis_tasks

                    else:
                        # Append '-manual' to the name if there's no OVAL data and Enabled=False
                        task['name'] += ' - manual'
                        task['enabled'] = 'false'

                    tasks.append(task)
            else:
                # Original logic for when rule_elements is a dictionary
                for t, r in rule_elements.items():
                    if rule['id'] in r:
                        tags.append(t)
                        rule_name = re.sub(r'_', ' ', rule['id'].split(f'{rule["number"]}_')[1].strip())
                        tags.append(f'rule_{rule["number"]}')
                        tags.append(baseline)

                        check_type=''
                        if group['title'] in ['Password Policy', 'Account Lockout Policy', 'User Rights Assignment', 'Accounts']:
                            check_type = 'security_policy'
                        
                        complex_checks = extract_complex_checks(rule)

                        desc = "".join(char for char in rule.get('description','') if char.isalnum() or char in [' ', '.', '/', '\\', ',','!','\n'])

                        remediation_advice = rule.get('fixtext','No remediation listed.')

                        # Initialize task with common elements
                        task = {
                            'name': rule_name,
                            'id': rule.get('id'),
                            'number': rule.get('number'),
                            'impact': rule.get('impact'),
                            'description': desc,
                            'cis_section': group['title'],
                            'tags': tags,
                            'enabled': 'true',
                            'complex_check': rule.get('complex_check'),
                            'complex_checks': complex_checks,
                            'check_type': check_type or 'Undefined',
                            'remediation_advice': remediation_advice
                        }

                        # Check if there's matching OVAL data
                        oval_match = next((oval_data for oval_id, oval_data in oval_map.items() 
                                           if rule['id'] == oval_data['xccdf_id']), None)
                        if oval_match:
                            task.update({
                                'oval_id': next(oval_id for oval_id, oval_data in oval_map.items() 
                                                if rule['id'] == oval_data['xccdf_id']),
                                'oval_description': oval_match['description'],
                                'oval_tests': oval_match['associated_tests'],
                            })

                            registry_checks = extract_registry_info(oval_match['associated_tests'], complex_checks)
                            if registry_checks:
                                if registry_checks[0]['registry_hive'] == 'HKEY_USERS':
                                    base_path = None
                                    for item in registry_checks:
                                        if base_path is None:
                                            base_path = item['registry_path']
                                        else:
                                            base_path += item['registry_path']
                                    
                                    merged_check = registry_checks[-1].copy()
                                    merged_check['registry_path'] = base_path
                                    task['registry_checks'] = [merged_check]
                                else:
                                    task['registry_checks'] = registry_checks

                            user_rights = extract_user_rights(oval_match['associated_tests'], rule)
                            if user_rights:
                                task['user_rights'] = user_rights

                            account_status = extract_account_status(oval_match['associated_tests'], rule)
                            if account_status:
                                task['account_status'] = account_status

                            wmi_checks = extract_wmi_tests(oval_match['associated_tests'])
                            if wmi_checks:
                                task['wmi_checks'] = wmi_checks

                            if 'cis_microsoft_iis' in baseline:
                                iis_tasks = extract_iis_tasks(oval_match['associated_tests'], rule)
                                if iis_tasks:
                                    task['iis_tasks'] = iis_tasks

                        else:
                            # Append '-manual' to the name if there's no OVAL data and Enabled=False
                            task['name'] += ' - manual'
                            task['enabled'] = 'false'

                        tasks.append(task)

    sort_by_number(tasks)
    manifest.extend(map(lambda t: f'{t["number"]} - {t["name"]}', tasks))
    render_tasks(tasks, filepath)
    with open(os.path.join(out_dir, 'manifest.txt'), 'w', encoding='utf-8') as file:
        file.write('\n'.join(manifest))

def get_tagged_rule_ids(profiles, profile_result):
    if not profile_result:
        raise Exception(f'Generator does not support the following profiles: {[p["id"] for p in profiles]}')

    def process_levels(levels):
        if isinstance(levels, (int, list)):
            return levels
        if len(levels) == 1:
            return list(levels.values())[0]
        
        sorted_levels = sorted(levels.keys())
        for i in range(1, len(sorted_levels)):
            levels[sorted_levels[i]] -= levels[sorted_levels[i-1]]
        return levels

    # Convert set to dictionary if necessary
    if isinstance(profile_result, set):
        profile_result = {list(profile_result)[0]: {}}
    elif not isinstance(profile_result, dict):
        raise TypeError(f"Expected dict or set, got {type(profile_result)}")

    return [
        {
            'suffix': product_type,
            'rules': process_levels(levels)
        }
        for product_type, levels in profile_result.items()
    ]

def process_levels(levels):
    # Sort levels and subtract lower levels from higher ones
    sorted_levels = sorted(levels.keys())
    processed_levels = {}
    for i, level in enumerate(sorted_levels):
        if i == 0:
            processed_levels[level] = levels[level]
        else:
            processed_levels[level] = levels[level] - levels[sorted_levels[i-1]]
    return processed_levels

def render_tasks(tasks, output_path):
  template = env.get_template('ansible_cis.yml.j2')
  result = template.render(tasks=tasks)
  with open(output_path, 'w', encoding='utf-8') as file:
    file.write(result)

def sort_by_number(items):
  items.sort(key=lambda item: [int(n) for n in item['number'].split('.')])