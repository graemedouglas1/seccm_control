gcs_scm_control
=========

Role created for use on Ansible Tower Infrastructure or Ansible Core to perform the following actions on State Street infrastructure:

* Check Compliance of Security Configuration
* Report on Compliance for further action

Requirements
------------

The ansible control role requires extra vars to be passed in at build time, and requires credential access to target nodes.

Role Variables
--------------

Role variables are passed through from the scm_data module and from Ansible Tower during runtime.

A sensible set of defaults can be found in vars/main.yml.

Dependencies
------------

The playbooks listed within this role require the following Galaxy modules to be available within the project during runtime in order to function correctly:

Galaxy Modules:

* ansible-windows
* community-general
* community-windows
* servicenow-servicenow
* community-hashi_vault
* ansible-tower

Author Information
------------------

GCS SecCM (Security Config Management) Team - State Street Corporation
