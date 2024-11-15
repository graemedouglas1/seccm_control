#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import sys
import re
import yaml

sys.path.append(os.path.abspath(os.path.join(os.getcwd(), "..", "project")))

from pathlib import Path
from ansible.errors import AnsibleParserError, AnsibleLookupError
from ansible.inventory.host import Host
from ansible.inventory.group import Group
from ansible.inventory.manager import InventoryManager
from ansible.module_utils._text import to_bytes, to_native
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.vars import BaseVarsPlugin
from ansible.template import Templar
from ansible.utils.display import Display
from ansible.vars.manager import VariableManager
from deepmerge import Merger
from jinja2 import Environment, FileSystemLoader
from vars_utils.support_functions import get_environment

def regex_search(value, pattern):
    return re.search(pattern, value) is not None
    
def regex_findall(value, pattern):
    return re.findall(pattern, value)

FOUND = {}

class VarsModule(BaseVarsPlugin):
    REQUIRES_ENABLED = True

    def __init__(self, *args, **kwargs):
        super(VarsModule, self).__init__(*args, **kwargs)
        self.loader = kwargs.get('loader')
        self.templar = kwargs.get('templar')
        self._options = kwargs.get('options', {})  # Initialize with an empty dict if not provided
        self.inventory = None
        self.variable_manager = None
        self._display = Display()
        
        if self.loader is None:
            self.loader = DataLoader()
    
        if self.templar is None and self.loader is not None:
            self.templar = Templar(loader=self.loader)

    def get_vars(self, loader, path, entities, cache=False):
        if not isinstance(entities, list):
            entities = [entities]

        super(VarsModule, self).get_vars(loader, path, entities)

        # Check if inventory is being pulled dynamically from Ansible Tower or AWX
        if os.environ.get('TOWER_INVENTORY_ID') or os.environ.get('AWX_INVENTORY_ID'):
            return {}  # Return empty dict if inventory is from Tower/AWX

        # Safely access self._options
        if self._options is None:
            self._options = getattr(loader, '_options', {})
        
        if not self._options:
            self._display.vvv("VarsModule: Options not properly initialized. Some functionality may be limited.")

        returned_data = {}
        for entity in entities:
            if isinstance(entity, Host):
                returned_data.update(self._get_host_vars(entity, cache))
            elif isinstance(entity, Group):
                continue
            else:
                raise AnsibleParserError(f"Supplied entity must be Host or Group, got {type(entity)} instead")

        return returned_data

    def _get_host_vars(self, entity, cache):
        # Implement error handling
        try:
            hostname = str(entity.name).lower()
            if cache and hostname in FOUND:
                return FOUND[hostname]

            config = self._load_config()
            node_vars = self._initialize_node_vars(entity, hostname)
            scm_data = self._process_data_modules(config, node_vars)
            
            returned_data = scm_data.copy()
            returned_data.update(node_vars)
            FOUND[hostname] = returned_data
            return returned_data
        except Exception as e:
            self._display.vvv(f"Error in _get_host_vars for {entity.name}: {str(e)}")
            return {}

    def _load_config(self):
        root_dir = os.path.abspath(os.path.join(os.getcwd(), ".."))
        config_yml = f"{root_dir}/project/vars_plugins/scm_config.yml"

        if not os.path.isfile(config_yml):
            raise AnsibleLookupError(f"Unable to load file: {config_yml}. Disabling scm_data plugin")

        with open(config_yml, 'r') as fd:
            return yaml.safe_load(fd)

    def _initialize_node_vars(self, entity, hostname):
        root_dir = os.path.abspath(os.path.join(os.getcwd(), ".."))
        node_vars = {
            'ansible_host': hostname,
            'root_dir': root_dir,
            'project_dir': f"{root_dir}/project",
            'roles_dir': f"{root_dir}/requirements_roles"
        }

        node_vars.update(self._get_inventory_vars())
        node_vars.update(self._get_ansible_facts(hostname))
        node_vars.update(getattr(entity, 'vars', {}))
        node_vars['host_groups'] = [group.name for group in entity.get_groups()]

        node_vars['towerEnvironment'] = get_environment('towerEnvironment')
        node_vars['snowEnvironment'] = get_environment('snowEnvironment')

        fqdn = node_vars.get('fqdn', '')
        if fqdn:
            matches = re.search(r'\.(\w+)\.', fqdn)
            if matches:
                node_vars['domain'] = matches.group(1).lower()

        return node_vars

    def _get_inventory_vars(self):
        if not self.inventory:
            inventory_sources = self._options.get('inventory') or os.environ.get('INVENTORY_SOURCES', '').split(',')
            if not inventory_sources or inventory_sources == ['']:
                inventory_sources = ['inventories/default_inv.py', '/runner/inventory/hosts']

            inventory_sources = [os.path.realpath(os.path.expanduser(i)) for i in inventory_sources]

            if self.loader is None:
                self.loader = DataLoader()
            self.inventory = InventoryManager(loader=self.loader, sources=inventory_sources)
            self.variable_manager = VariableManager(loader=self.loader, inventory=self.inventory)
        
        return self.variable_manager.get_vars()

    def _get_ansible_facts(self, hostname):
        ansible_yml = Path(f"/tmp/{hostname}_facts.yml")
        if ansible_yml.is_file():
            with open(ansible_yml, 'r') as fd:
                ansible_facts = yaml.safe_load(fd) or {}
            return {f"ansible_{k}": v for k, v in ansible_facts.items()}
        return {}

    def _process_data_modules(self, config, node_vars):
        merger = self._configure_merger(config)
        scm_data = {}

        for data_module in config['plugin_options']['data_modules']:
            data_yml_folder = f"{node_vars['roles_dir']}/{data_module}"
            env_loader_path = os.path.abspath(data_yml_folder)

            if not os.path.isdir(env_loader_path):
                self._display.vvv(f"Data module directory does not exist: {env_loader_path}")
                continue

            env = Environment(loader=FileSystemLoader(env_loader_path))
            
            # Add filters to jinja2 templates
            env.filters['regex_search'] = regex_search
            env.filters['regex_findall'] = regex_findall

            try:
                template = env.get_template('hiera.yml')
                result = template.render(node_vars)
                fd_data = yaml.safe_load(result) or {}

                data_dir = os.path.join(node_vars['roles_dir'], data_module, fd_data.get('defaults', {}).get('datadir', ''))
                hierarchy = self._build_hierarchy(fd_data, node_vars['ansible_host'])

                found_files = self._find_var_files(data_dir, hierarchy)
                scm_data = self._merge_var_files(found_files, node_vars, scm_data, merger)

            except Exception as e:
                self._display.v(f"Error processing data module {data_module}: {to_native(e)}")

        return scm_data

    def _build_hierarchy(self, fd_data, hostname):
        return [
            path.lower()
            for item in fd_data.get('hierarchy', [])
            if 'scope' in item and (
                'all' in item['scope'] or
                ('hosts' in item['scope'] and 'localhost' not in hostname) or
                ('localhost' in item['scope'] and 'localhost' in hostname)
            )
            for paths in item.get('paths', [])
            for path in paths.get('paths', [])
        ]

    def _find_var_files(self, data_dir, hierarchy):
        found_files = []
        for var_path in hierarchy:
            opath = os.path.realpath(os.path.join(data_dir, var_path))
            b_opath = to_bytes(opath)

            if os.path.isdir(b_opath):
                if self.loader is not None:
                    found = self.loader.find_vars_files(os.path.dirname(opath), os.path.basename(var_path))
                    found_files.extend(found)
                else:
                    self._display.vvv("Loader is not available, skipping var file search")
            elif os.path.isfile(b_opath):
                # If it's a file, add it directly to the found_files list
                found_files.append(opath)
            else:
                self._display.vvv(f"Path does not exist, skipping: {opath}")

        return found_files

    def _merge_var_files(self, found_files, node_vars, scm_data, merger):
        if self.loader is None or self.templar is None:
            self._display.vvv("Loader or Templar is not available, skipping var file merging")
            return scm_data

        templar = Templar(loader=self.loader, variables=node_vars)
        for found in found_files:
            self._display.v(f"Importing: {found}")
            temp_data = self.loader.load_from_file(found, cache=False, unsafe=True) or {}
            new_data = templar.template(temp_data) or {}
            scm_data = merger.merge(scm_data, new_data)
        return scm_data

    def _configure_merger(self, config):
        hash_behavior = config['plugin_options']['merge']['hash_behavior']
        list_behavior = config['plugin_options']['merge']['list_behavior']
        return Merger(
            [(list, [list_behavior]), (dict, [hash_behavior]), (set, ["union"])],
            ["override"],
            ["override"]
        )