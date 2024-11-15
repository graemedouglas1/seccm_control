#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time, datetime, os, base64, uuid, re, sys, jinja2, requests, json, urllib3

from urllib3.util import Timeout, Retry
from ansible.errors import AnsibleError
from ansible.errors import AnsibleFilterError
from ansible.module_utils._text import to_native
from collections import defaultdict
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from requests.auth import HTTPBasicAuth

class SCMModule(object):
    
    def decode(self, value):
        try:
            b64bytes = value.encode('ascii')
            msgbytes = base64.b64decode(b64bytes)
            str_decode = msgbytes.decode('ascii')

            return str_decode
        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during decode, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during decode, this was the original exception: %s" % to_native(e))
    
    def generate_key(self, pw, salt = None):
        if salt is None:
            unique = uuid.uuid4()
            salt = bytes(unique.hex,'utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return salt, base64.urlsafe_b64encode(kdf.derive(pw.encode('utf-8')))
    
    def get_auth_token(self, url, encoded_body):
        try:
            retries  = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout  = Timeout(connect=2.0, read=7.0)
            http     = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)
            response = http.request(method='POST', url=url, body=encoded_body)  

            if (response.status == 200):
                data         = response.data
                json_obj     = json.loads(data)
                client_token = str(json_obj['auth']['client_token'])
              
                return client_token
            else:
                raise AnsibleError('AuthToken Not Provided by Service. Please Check Details and Try Again.')

        except urllib3.exceptions.HTTPError as errh:
             raise AnsibleError('HTTPError: %s' % (errh))
        except urllib3.exceptions.ConnectionError as errc:
            raise AnsibleError('ConnectionError: %s' % (errc))
        except urllib3.exceptions.TimeoutError as errt:
            raise AnsibleError('Timeout: %s' % (errt))
        except urllib3.exceptions.RequestError as err:
            raise AnsibleError('RequestException: %s' % (err))

    def get_tower_env(self, value):
        try:
          if 'vm-tws' in value:
              return 'azlab'
          elif 'automation-ansible-devtest' in value:
              return 'devtest'
          elif 'automation-ansible-dev' in value:
              return 'dev'
          elif 'automation-ansible-uat' in value:
              return 'uat'
          elif 'automation-ansible-prd' in value:
              return 'production'
          else:
              raise AnsibleError('No Tower Environment Match')

        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during get_tower_env, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during get_tower_env, this was the original exception: %s" % to_native(e))

    def get_snow_criticality(self, value):
        try:
          if '1' in value:
              return '1 - most critical'
          elif '2' in value:
              return '2 - somewhat critical'
          elif '3' in value:
              return '3 - less critical'
          elif '4' in value:
              return '4 - not critical'
          else:
              raise AnsibleFilterError('No criticality match')
        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during get_snow_criticality, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during get_snow_criticality, this was the original exception: %s" % to_native(e))

    def get_snow_operatingsystem(self, value):
        try:
          if 'Windows 2019 Standard' in value:
              return 'Windows Server 2019 Standard'
          elif 'Windows 2019 Datacenter' in value:
              return 'Windows Server 2019 Datacenter'
          elif 'Windows 2022 Standard' in value:
              return 'Windows Server 2022 Standard'
          elif 'Windows 2022 Datacenter' in value:
              return 'Windows Server 2022 Datacenter'
          else:
              raise AnsibleFilterError('No operatingsystem match')
        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during get_snow_operatingsystem, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during get_snow_operatingsystem, this was the original exception: %s" % to_native(e))

    def increment(self, value):
        try:
          separator = "."
          part_ver  = 1          
          arr = value.split(".")
          
          arr[part_ver] = str(int(arr[part_ver]) + 1)
        
          if (part_ver < 2):
              arr[2] = str('0')
          if (part_ver < 1):
              arr[1] = str('0')
          
          return separator.join(str(x) for x in arr)

        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during increment, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during increment, this was the original exception: %s" % to_native(e))

    def merge(self, value):
        try:
          flat = defaultdict(list)
          for hash in args:
              for key in hash:
                  flat[key].append(hash[key])
          merged = {}
          for key in flat:
              dict_instances = [isinstance(v, dict) for v in flat[key]]
              if any(dict_instances):
                  merged[key] = merge(*flat[key])
              else:
                  merged[key] = merge_sum(flat[key])
          return merged
        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during Merge, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during Merge, this was the original exception: %s" % to_native(e))

    def merge_sum(iterable):
        start = 0
        if isinstance(iterable[0], list):
            start = []
        return sum(iterable, start)

    def netmask_to_cidr(self, value):
        try:
            cidr_notation = sum([bin(int(x)).count('1') for x in value.split('.')])
            return cidr_notation
        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during CIDR conversion, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during CIDR conversion, this was the original exception: %s" % to_native(e))
            
    def query_api(self, uri, user=None, pwd=None, headers=None, body=None, method=None, verify=False):
        try:
            if method == 'POST':
                if headers is None:
                    response = requests.post(url=uri, headers={'accept': 'application/json'}, auth=HTTPBasicAuth(f'{user}',f'{pwd}'), verify=False)
                else:
                    response = requests.post(url=uri, headers=headers, json=body, verify=False)
            else:
                    response = requests.get(url=uri, headers=headers, verify=False)
            
            if (response.status_code == 200):
                return response.json()
            elif (response.status_code == 404):
                return None

            response.raise_for_status()

        # return empty value if error during request
        except requests.exceptions.HTTPError as errh:
             raise AnsibleFilterError('HTTPError: %s' % (errh))
        except requests.exceptions.ConnectionError as errc:
            raise AnsibleFilterError('ConnectionError: %s' % (errc))
        except requests.exceptions.Timeout as errt:
            raise AnsibleFilterError('Timeout: %s' % (errt))
        except requests.exceptions.RequestException as err:
            raise AnsibleFilterError('RequestException: %s' % (err))

    def rewrap(self, value):
        try:
            ciphertext  = value[0]
            decrypt_key = value[1]
            encrypt_key = value[2]

            unwrap_payload = [ciphertext, decrypt_key]
            cleartext      = self.unwrap(unwrap_payload)

            wrap_payload = [cleartext, encrypt_key]
            encoded_str  = self.sensitive(wrap_payload)
            return encoded_str

        except jinja2.exceptions.UndefinedError as e:
            raise AnsibleUndefinedVariable("Something happened during rewrap, this was the original exception: %s" % to_native(e))
        except Exception as e:
            raise AnsibleFilterError("Something happened during rewrap, this was the original exception: %s" % to_native(e))

    def sensitive(self, value):
        if value and value is not None:
            if isinstance(value, list):
                cleartext = value[0]
            elif isinstance(value, str):
                cleartext = value
            else:
                raise AnsibleFilterError("Unable to extract value")
            
            try:
                if isinstance(value, list):
                    encrypt_key = value[1]
                elif isinstance(value, str):
                    if 'SSC_TOWER_URL' in os.environ:
                        encrypt_key = str(os.getenv('SSC_TOWER_URL')).lower()
                    elif 'AWX_HOST' in os.environ:
                        encrypt_key = str(os.getenv('AWX_HOST')).lower()
                    elif 'TOWER_HOST' in os.environ:
                        encrypt_key = str(os.getenv('TOWER_HOST')).lower()
                    else:
                        raise AnsibleFilterError("Unable to detect encryption key")
                else:
                    raise AnsibleFilterError("Unable to obtain encryption key")

                salt, key = self.generate_key(encrypt_key)
                f = Fernet(key)
                ciphertext = f.encrypt(cleartext.encode())
                ciphertext_with_salt = salt + ciphertext
                ciphertext_with_salt = ciphertext_with_salt.decode()
                return ciphertext_with_salt

            except jinja2.exceptions.UndefinedError as e:
                raise AnsibleUndefinedVariable("Something happened during sensitive, this was the original exception: %s" % to_native(e))
            except Exception as e:
                raise AnsibleFilterError("Something happened during sensitive, this was the original exception : %s" % to_native(e))
        else:
            return None

    def unwrap(self, value):
        if value and value is not None:
            if isinstance(value, list):
                ciphertext = value[0]
            elif isinstance(value, str):
                ciphertext = value
            else:
                raise AnsibleFilterError("Unable to extract value")

            salt = ciphertext[0:32]
            ciphertext_no_salt = ciphertext[32:]

            try:
                if isinstance(value, list):
                    decrypt_key = value[1]
                elif isinstance(value, str):
                    if 'SSC_TOWER_URL' in os.environ:
                        decrypt_key = str(os.getenv('SSC_TOWER_URL')).lower()
                    elif 'AWX_HOST' in os.environ:
                        decrypt_key = str(os.getenv('AWX_HOST')).lower()
                    elif 'TOWER_HOST' in os.environ:
                        decrypt_key = str(os.getenv('TOWER_HOST')).lower()
                    else:
                        raise AnsibleFilterError("Unable to detect decryption key")
                else:
                    raise AnsibleFilterError("Unable to obtain decryption key")

                salt, key = self.generate_key(decrypt_key, bytes(salt,'utf-8'))
                f = Fernet(key)
                encrypted_value = bytes(ciphertext_no_salt, 'utf-8')
                decrypted_value = f.decrypt(encrypted_value).decode()
                return decrypted_value

            except jinja2.exceptions.UndefinedError as e:
                raise AnsibleUndefinedVariable("Something happened during unwrap, this was the original exception: %s" % to_native(e))
            except Exception as e:
                raise AnsibleFilterError("Something happened during unwrap, this was the original exception : %s" % to_native(e))
        else:
            return None

    def urljoin(self, *args):
        trailing_slash = '/' if args[-1].endswith('/') else ''
        return '/'.join([str(x).strip('/') for x in args]) + trailing_slash

    def vlookup(self, url, method, headers, vault_key, input_data, kv_v2):
        try:
            json_obj = {}
            
            retries  = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout  = Timeout(connect=2.0, read=7.0)
            http     = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)

            if method == 'GET':
                response = http.request(method=method, url=url, headers=headers)
            
                if (response.status == 200):
                    data = response.data
                    json_obj = json.loads(data)
                    
                    if vault_key:
                        if kv_v2:
                            return [json_obj['data']['data'][vault_key]]
                        else:
                            return [json_obj['data'][vault_key]]
                    else:
                        if kv_v2:
                            return json_obj['data']['data'].keys()
                        else:
                            return json_obj['data'].keys()
                else:
                    raise AnsibleError('Response {0} on URL: {1}:{2}'.format(response.status, url, vault_key))

            elif method == 'POST':
                response = http.request(method='POST', url=url, headers=headers, body=input_data)
            
                if (response.status == 200):
                    return response.status
                else:
                    raise AnsibleError('Response {0} on URL: {1}'.format(response.status, url))
                    
        except urllib3.exceptions.HTTPError as errh:
             raise AnsibleError('HTTPError: %s' % (errh))
        except urllib3.exceptions.ConnectionError as errc:
            raise AnsibleError('ConnectionError: %s' % (errc))
        except urllib3.exceptions.TimeoutError as errt:
            raise AnsibleError('Timeout: %s' % (errt))
        except urllib3.exceptions.RequestError as err:
            raise AnsibleError('RequestException: %s' % (err))
