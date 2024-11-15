
#!/usr/bin/python
# coding: utf-8

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.git_actions import GitActions

def main():
    module = AnsibleModule(
        argument_spec={
            "path": dict(required=True, type="path"),
            "executable": dict(type="path"),
            "comment": dict(type="str"),
            "add": dict(default=".", type="list", elements="str"),
            "ssh_params": dict(type="dict"),
            "scm_branch": dict(default="main"),
            "pull": dict(type="bool", default=False),
            "pull_options": dict(default=["--no-edit"], type="list", elements="str"),
            "push": dict(type="bool", default=True),
            "push_option": dict(type="str"),
            "add_option": dict(type="str"),
            "push_force": dict(type="bool", default=False),
            "allow_empty": dict(type="bool", default=False),
            "url": dict(required=True, no_log=True),
            "clean": dict(type="str", choices=["ignored", "untracked", "all"]),
        },
        required_together=[("comment", "add")],
        required_one_of=[("add", "pull", "push")]
    )

    params = module.params
    result = {"changed": False}

    set_environment_variables(module)
    validate_url(module, params["url"], params["ssh_params"])

    git_actions_instance = GitActions(module)
    changed_files, untracked = git_actions_instance.status()

    if all([changed_files, untracked, params["clean"]]):
        result.update(git_actions_instance.clean())
    else:
        result.update(perform_git_operations(git_actions_instance, params))

    module.exit_json(**result)

def set_environment_variables(module):
    module.run_command_environ_update = {
        var: "C.UTF-8" for var in ["LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE"]
    }

def validate_url(module, url, ssh_params):
    if url.startswith("https://") and ssh_params:
        module.warn('SSH Parameters will be ignored as "https" in url')
    elif url.startswith("ssh://git@github.com"):
        module.fail_json(msg='GitHub does not support "ssh://" URL. Please remove it from url')

def perform_git_operations(git_actions_instance, params):
    result = {}

    if params["pull"]:
        result.update(git_actions_instance.pull())
    
    if "main" not in params["scm_branch"]:
        result.update(git_actions_instance.checkout())

    git_actions_instance.add()

    commit_result = git_actions_instance.commit()
    result.update(commit_result)

    if not commit_result["git_commit"]["changed"]:
        return {"warnings": commit_result["git_commit"]["output"]}

    if params["push"]:
        result.update(git_actions_instance.push())
    
    result["changed"] = True
    return result

if __name__ == "__main__":
    main()