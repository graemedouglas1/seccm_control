#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os, sys, base64, uuid, re, jinja2, requests, json

# Add project path for module searching
sys.path.append(os.path.abspath(os.path.join(os.getcwd(),"..","project")))

# Importing scm functions module
from module_utils.scm_functions import SCMModule
scm_module = SCMModule()

class FilterModule(object):
    
    def filters(self):
        return {
            'decode': scm_module.decode,
            'sensitive': scm_module.sensitive,
            'unwrap': scm_module.unwrap,
            'merge': scm_module.merge,
            'get_snow_criticality': scm_module.get_snow_criticality,
            'get_snow_operatingsystem': scm_module.get_snow_operatingsystem,
            'get_tower_env': scm_module.get_tower_env,
            'increment': scm_module.increment,
            'netmask_to_cidr': scm_module.netmask_to_cidr
        }
