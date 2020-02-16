#!/usr/bin/env python

from __future__ import print_function

import time
import logging
import os
import platform


class SshConnector(object):
    """SSH paramiko wrapper class."""

    def __init__(self, ip_address, username, password, retry_count=3):
        try:
            self.paramiko = __import__("paramiko")
        except ImportError:
            self.dependencies_install()
            self.paramiko = __import__("paramiko")
        self.logger = logging.getLogger("SshConnector")
        self.ip = ip_address
        self.user = username
        self.password = password
        self.retries = retry_count
        self.connector, self.connection_status = self._connect()

    @staticmethod
    def define_os():
        """Gets os type name"""

        return platform.dist()[0]

    def dependencies_install(self):
        """Install dependencies in order to use paramiko module."""

        if self.define_os() != "centos":
            raise EnvironmentError("To install dependencies on systems other than CentOS")
        local_connector = ConnectorBase.create_connector("local")
        ignore_deprecation = "PYTHONWARNINGS=ignore:DEPRECATION "
        pip_up = "pip install --upgrade pip"
        modules_inst = "pip install --no-cache-dir --progress-bar off" \
                       " paramiko" \
                       " cryptography"
        packages_inst = "yum install -y -q" \
                        " openssh-server" \
                        " openssh-clients" \
                        " sshpass"
        local_connector.exec_cmd(packages_inst)
        local_connector.exec_cmd(ignore_deprecation + pip_up)
        local_connector.exec_cmd(ignore_deprecation + modules_inst)

    def _check_connection(self):
        """This will check if the connection is still available."""

        try:
            self.exec_cmd('ls')
            return True
        except AttributeError:
            return False

    def _connect(self):
        """Performs connection to the destination address and returns connector object."""

        attempts = 0
        while True:
            try:
                ssh = self.paramiko.SSHClient()
                ssh.set_missing_host_key_policy(self.paramiko.AutoAddPolicy())
                ssh.connect(self.ip,
                            username=self.user,
                            password=self.password)
                break
            except self.paramiko.AuthenticationException:
                raise AuthenticationFailed(self.ip)
            except Exception:
                print("Retrying to establish connection to %s ..." % self.ip)
                attempts += 1
                time.sleep(2)
            if attempts >= self.retries:
                raise FailedToConnect(self.ip)
        self.logger.debug("Connection with %s established", self.ip)
        return ssh, self._check_connection()

    def close(self):
        """Close ssh connection."""

        self.connector.close()
        self.logger.debug("Connection to %s was closed", self.ip)

    def reload(self):
        """Reload connection."""

        self.close()
        connector, _ = self._connect()
        return self._check_connection()

    def exec_cmd(self, command, show_rc=False):
        """Executes one command on target and returns an output."""

        self.logger.debug("CMD: %s", command)
        stdin, stdout, stderr = self.connector.exec_command(command)
        return_code = stdout.channel.recv_exit_status()
        if return_code == 127:
            self.logger.debug("CMD: %s wasn't found", command)
            raise CmdFailed(command, return_code)
        elif return_code:
            output = return_code, stderr.read()
        else:
            output = return_code, stdout.read()
        return output if show_rc else output[1]

