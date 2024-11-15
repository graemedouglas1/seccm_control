import os, ssl, urllib3, ansible.utils, warnings

from ansible.utils.display import Display
from distutils.version import StrictVersion
from sys import version_info
from urllib3.util import Timeout, Retry
from ansible.errors import AnsibleError

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

try:
    import json
except ImportError:
    import simplejson as json

try:
    from ansible.plugins.lookup import LookupBase
except ImportError:
    # ansible-1.9.x
    class LookupBase(object):
        def __init__(self, basedir=None, runner=None, **kwargs):
            self._display = Display()
            self.runner   = runner
            self.basedir  = basedir or (self.runner.basedir
                                       if self.runner
                                       else None)

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        def get_basedir(self, variables):
            return self.basedir

class LookupModule(LookupBase):
    
    def _urljoin(self, *args):
        trailing_slash = '/' if args[-1].endswith('/') else ''
        return '/'.join([str(x).strip('/') for x in args]) + trailing_slash

    def _get_auth_token(self, url, encoded_body):
        try:
            retries  = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout  = Timeout(connect=2.0, read=7.0)
            http     = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)

            response = http.request(method='POST', url=url, body=encoded_body)  

            self._display.v("Token Status: {0}".format(response.status))

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

    def _vlookup(self, url, headers, vault_key, kv_v2):
        try:
            json_obj = {}
            
            retries  = Retry(total=10, raise_on_status=False, backoff_factor=1, status_forcelist=[429,500,502,503,504])
            timeout  = Timeout(connect=2.0, read=7.0)
            http     = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, retries=retries, timeout=timeout)
            response = http.request(method='GET', url=url, headers=headers)  

            self._display.v("Lookup Status: {0}".format(response.status))
            
            if (response.status == 200):
                data = response.data
                json_obj = json.loads(data)
               
                if kv_v2:
                    return [json_obj['data']['data'][vault_key]]
                else:
                    return [json_obj['data'][vault_key]]
            else:
                raise AnsibleError('Response {0} on URL: {1}:{2}'.format(response.status, url, vault_key))

        except urllib3.exceptions.HTTPError as errh:
             raise AnsibleError('HTTPError: %s' % (errh))
        except urllib3.exceptions.ConnectionError as errc:
            raise AnsibleError('ConnectionError: %s' % (errc))
        except urllib3.exceptions.TimeoutError as errt:
            raise AnsibleError('Timeout: %s' % (errt))
        except urllib3.exceptions.RequestError as err:
            raise AnsibleError('RequestException: %s' % (err)) 

    def run(self, terms, inject=None, variables=None, **kwargs):

        if isinstance(terms, list):
            parameters = [x.strip() for x in terms[0].split(', ')]
        else:
            parameters = []
        
        try:
            parameter_bag = {}
            for parameter in parameters:
                parameter_split = parameter.split('=')
                
                parameter_key   = parameter_split[0]
                parameter_value = parameter_split[1]
                parameter_bag[parameter_key] = parameter_value
            
            json_string = json.dumps(parameter_bag)
            lookup_data = json.loads(json_string)
        except:
            lookup_data = None

        self._display.v("lookup_data: {0}".format(lookup_data))

        if lookup_data:

            try:
                if 'vault_instance' in lookup_data:
                    vault_instance = str(lookup_data['vault_instance']).lower()
                elif os.getenv('active_vault_instance') is not None:
                    vault_instance = os.getenv('active_vault_instance')
                    vault_instance = str(vault_instance).lower()
                else:
                    vault_instance = None
            except:
                vault_instance = None
            if not vault_instance:
                raise AnsibleError('vault_instance not set. Specify with ACTIVE_VAULT_INSTANCE environment variable or vault_instance=value')

            try:
                if 'auth_method' in lookup_data:
                    auth_method = str(lookup_data['auth_method']).lower()
                elif os.getenv('vault_auth_method') is not None:
                    auth_method = os.getenv('vault_auth_method')
                    auth_method = str(auth_method).lower()
                else:
                    auth_method = None
            except:
                auth_method = None
            if not auth_method:
                raise AnsibleError('auth_method not set. Specify with VAULT_AUTH_METHOD environment variable or auth_method=value')
                
            try:
                if 'namespace' in lookup_data:
                    namespace = str(lookup_data['namespace']).lower()
                elif os.getenv('vault_namespace') is not None:
                    namespace = os.getenv('vault_namespace')
                    namespace = str(namespace).lower()
                else:
                    namespace = None
            except:
                namespace = None
            if not namespace:
                raise AnsibleError('namespace not set. Specify with VAULT_NAMESPACE environment variable or namespace=value')         

            try:
                if 'vault_url' in lookup_data:
                    vault_url = str(lookup_data['vault_url']).lower()
                elif os.getenv('{0}_vault_url'.format(vault_instance)) is not None:
                    vault_url = os.getenv('{0}_vault_url'.format(vault_instance))
                    vault_url = str(vault_url).lower()
                else:
                    vault_url = None
            except:
                vault_url = None
            if not vault_url:
                raise AnsibleError('vault_url not set. Specify with {0}_VAULT_URL environment variable or vault_url=value'.format(vault_instance))

            try:
                path = lookup_data['path']
            except:
                path = None
            if not path:
                raise AnsibleError('path not set. Specify with path=value')          

            try:
                vault_key = lookup_data['vault_key']
            except:
                vault_key = None
            if not vault_key:
                raise AnsibleError('vault_key not set. Specify with vault_key=value')

            try:
                kv_v2 = lookup_data['kv_v2']
            except:
                kv_v2  = True

        else:
            raise AnsibleError('Lookup data not found')

        # Determine lookup type based on auth_method
        if auth_method == 'token':
            
            self._display.v("Running Vault Lookup With Token Based Authentication")
            
            try:
                if 'vault_token' in lookup_data:
                    token = str(lookup_data['vault_token']).lower()
                elif os.getenv('win_token') is not None:
                    token = os.getenv('win_token')
                    token = str(token).lower()
                else:
                    try:
                        with open(os.path.join(os.getenv('HOME'), '.vault-token')) as file:
                            token = file.read()
                    except IOError:
                        # token not found in file is same case below as not found in env var
                        pass
            except:
                token = None
            if not token:
                raise AnsibleError('token not set. Specify with WIN_TOKEN environment variable or vault_token=value or $HOME/.vault-token')

            # Setup url and headers
            query_url = self._urljoin(vault_url, 'v1', lookup_data['path'])
            headers   = { "X-Vault-Token": '{0}'.format(token),
                          "X-Vault-Namespace": '/{0}'.format(namespace),
                          "accept": "*/*" }

            # Request secret from vault
            return self._vlookup(query_url, headers, vault_key, kv_v2)
     
        elif auth_method == 'approle':
            
            self._display.v("Running Vault Lookup With Role Based Authentication")

            # Gather from Environment Variables
            try:                
                if 'role_id' in lookup_data:
                    role_id = str(lookup_data['role_id']).lower()
                elif os.getenv('{0}_vault_roleid'.format(vault_instance)) is not None:
                    role_id = os.getenv('{0}_vault_roleid'.format(vault_instance))
                    role_id = str(role_id).lower()
                else:
                    role_id = None
            except:
                role_id = None
            if not role_id:
                raise AnsibleError('role_id not set. Specify with {0}_VAULT_ROLEID environment variable or role_id=value'.format(vault_instance))

            try:
                if 'secret_id' in lookup_data:
                    secret_id = str(lookup_data['secret_id']).lower()
                elif os.getenv('{0}_vault_secretid'.format(vault_instance)) is not None:
                    secret_id = os.getenv('{0}_vault_secretid'.format(vault_instance))
                    secret_id = str(secret_id).lower()
                else:
                    secret_id = None
            except:
                secret_id = None
            if not secret_id:
                raise AnsibleError('secret_id not set. Specify with {0}_VAULT_SECRETID environment variable or secret_id=value'.format(vault_instance))

            # Get vault session token
            login_url = self._urljoin(vault_url, 'v1', namespace, 'auth/approle/login')
            encoded_body = json.dumps({
                    "role_id": '{}'.format(role_id),
                    "secret_id": '{}'.format(secret_id)
            })

            client_token = self._get_auth_token(login_url, encoded_body)

            # Use vault session token
            query_url = self._urljoin(vault_url, 'v1', lookup_data['path'])
            headers   = { "X-Vault-Token": '{}'.format(client_token),
                          "X-Vault-Namespace": '{}'.format(namespace),
                          "accept": "*/*" }
            
            # Perform Lookup
            return self._vlookup(query_url, headers, vault_key, kv_v2)

        elif auth_method == 'vault_cert':
            
            self._display.v("Running Vault Lookup With Certificate Based Authentication")
            
            # TO BE DEVELOPED POST FUNCTIONALITY ENABLEMENT
            
            # CACERT path
            #cafile = os.getenv('VAULT_CACERT') or (variables or inject).get('vault_cacert')        
            #if not cafile:
            #    raise AnsibleError('ca cert not set. Specify with'
            #                       ' VAULT_CACERT environment variable or vault_cacert Ansible variable')

            #capath = os.getenv('VAULT_CAPATH') or (variables or inject).get('vault_capath')
            #if not capath:
            #    raise AnsibleError('ca path not set. Specify with'
            #                       ' VAULT_CACERT environment variable or vault_cacert Ansible variable')
                        
            #if cafile or capath:
            #    context = ssl.create_default_context(cafile=cafile, capath=capath)
            #else:
            #    context = None

        else:
            raise AnsibleError('auth_method passed in does not match: [token, approle]')