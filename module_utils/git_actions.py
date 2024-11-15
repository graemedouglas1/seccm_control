from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import stat
import tempfile

from ansible.module_utils.six import b

class GitActions:
    def __init__(self, module):
        self.module = module
        self.url = module.params["url"]
        self.path = module.params["path"]
        self.clean = module.params["clean"]
        self.scm_branch = module.params["scm_branch"]
        self.git_path = module.params["executable"] or module.get_bin_path("git", True)

        self._setup_ssh(module)

    def _setup_ssh(self, module):
        ssh_params = module.params.get("ssh_params", {})
        ssh_key_file = ssh_params.get("key_file")
        ssh_opts = ssh_params.get("ssh_opts")
        ssh_accept_hostkey = ssh_params.get("accept_hostkey", False)

        if ssh_accept_hostkey:
            ssh_opts = (ssh_opts or "") + " -o StrictHostKeyChecking=no"

        self.ssh_wrapper = self._write_ssh_wrapper(module.tmpdir)
        self._set_git_ssh(self.ssh_wrapper, ssh_key_file, ssh_opts)
        module.add_cleanup_file(path=self.ssh_wrapper)

    def _write_ssh_wrapper(self, module_tmpdir):
        try:
            if os.access(module_tmpdir, os.W_OK | os.R_OK | os.X_OK):
                fd, wrapper_path = tempfile.mkstemp(prefix=module_tmpdir + "/")
            else:
                raise OSError
        except (IOError, OSError):
            fd, wrapper_path = tempfile.mkstemp()

        with os.fdopen(fd, "w+b") as fh:
            fh.write(b("""#!/bin/sh
if [ -z "$GIT_SSH_OPTS" ]; then
    BASEOPTS=""
else
    BASEOPTS=$GIT_SSH_OPTS
fi

BASEOPTS="$BASEOPTS -o BatchMode=yes"

if [ -z "$GIT_KEY" ]; then
    ssh $BASEOPTS "$@"
else
    ssh -i "$GIT_KEY" -o IdentitiesOnly=yes $BASEOPTS "$@"
fi
"""))

        os.chmod(wrapper_path, os.stat(wrapper_path).st_mode | stat.S_IEXEC)
        return wrapper_path

    def _set_git_ssh(self, ssh_wrapper, key_file, ssh_opts):
        os.environ["GIT_SSH"] = ssh_wrapper
        if key_file:
            os.environ["GIT_KEY"] = key_file
        if ssh_opts:
            os.environ["GIT_SSH_OPTS"] = ssh_opts

    def add(self):
        add = self.module.params["add"]
        add_option = self.module.params["add_option"]

        command = [self.git_path, "add"]
        if add_option:
            command.append(add_option)
        command.extend(["--"] + add)

        rc, output, error = self.module.run_command(command, cwd=self.path)
        if rc != 0:
            self._failing_message(rc, command, output, error)

    def checkout(self):
        command = [self.git_path, "checkout", "-b", self.scm_branch]
        rc, output, error = self.module.run_command(command, cwd=self.path)
        git_checkout = {"output": output, "error": error, "changed": rc == 0}
        if rc not in (0, 1):
            self._failing_message(rc, command, output, error)
        return {"git_checkout": git_checkout}

    def status(self):
        command = [self.git_path, "status", "--porcelain"]
        rc, output, error = self.module.run_command(command, cwd=self.path)
        if rc != 0:
            self._failing_message(rc, command, output, error)

        data = set()
        untracked = False
        for line in output.split("\n"):
            file_name = line.split(" ")[-1].strip()
            if file_name:
                data.add(file_name)
        if "Untracked" in output:
            untracked = True

        return data, untracked

    def commit(self):
        comment = self.module.params["comment"]
        allow_empty = self.module.params["allow_empty"]

        command = [self.git_path, "commit", "-m", comment]
        if allow_empty:
            command.insert(2, "--allow-empty")

        rc, output, error = self.module.run_command(command, cwd=self.path)
        git_commit = {"output": output, "error": error, "changed": rc == 0}
        if rc not in (0, 1):
            self._failing_message(rc, command, output, error)
        return {"git_commit": git_commit}

    def pull(self):
        command = [
            self.git_path,
            "-C",
            self.path,
            "pull",
            self.url,
            self.module.params["branch"],
        ] + self.module.params["pull_options"]
        rc, output, error = self.module.run_command(command)
        if rc != 0:
            self._failing_message(rc, command, output, error)
        return {"git_pull": {"output": output, "error": error, "changed": True}}

    def push(self):
        command = [self.git_path, "push", self.url, self.scm_branch]
        push_option = self.module.params.get("push_option")
        if push_option:
            command.insert(3, f"--push-option={push_option}")
        if self.module.params.get("push_force"):
            command.append("--force")

        rc, error, output = self.module.run_command(command, cwd=self.path)
        if rc != 0:
            self._failing_message(rc, command, output, error)
        return {"git_push": {"output": str(output), "error": str(error), "changed": True}}

    def clean_files(self):
        command = [self.git_path, 'clean', '-fd']
        if self.clean != 'untracked':
            command.append('-X')

        rc, error, output = self.module.run_command(command, cwd=self.path)
        if rc != 0:
            self._failing_message(rc, command, output, error)
        return {"git_clean": {"output": str(output), "error": str(error), "changed": True}}

    def _failing_message(self, rc, command, output, error):
        self.module.fail_json(
            rc=rc,
            msg=f"Error in running '{' '.join(command)}' command",
            command=" ".join(command),
            stdout=output,
            stderr=error,
        )