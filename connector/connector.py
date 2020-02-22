#!/usr/bin/env python

from __future__ import print_function

import glob
import logging
import os
import telnetlib
import time
from subprocess import check_output, PIPE, CalledProcessError

import paramiko


class Error(Exception):

    def __repr__(self):
        return self.message

    __str__ = __repr__


class AuthenticationFailed(Error):
    def __init__(self, ip):
        Error.__init__(self, "Authentication failed when connecting to %s" % ip)


class FailedToConnect(Error):
    def __init__(self, ip):
        Error.__init__(self, "Could not connect to %s" % ip)


class CmdFailed(Error):
    def __init__(self, command, return_code):
        Error.__init__(self, "The command wasn't found: %s, received RC=%d" % (command, return_code))


class ConnectorBase(object):

    @staticmethod
    def create_connector(conn_type, *args, **kwargs):
        if conn_type == "ssh":
            conn_obj = SshConnector(*args, **kwargs)
        elif conn_type == "local":
            conn_obj = LocalConnector()
        else:
            raise NotImplemented("%s hasn't implemented yet", conn_type)
        return conn_obj

    def exec_cmd(self, command, show_rc=False):
        raise NotImplemented("Method should be implemented in subclass")

    def exec_file_copy(self, *args, **kwargs):
        raise NotImplemented("Method should be implemented in subclass")


class LocalConnector(ConnectorBase):

    def __init__(self):
        self.logger = logging.getLogger("Connector.LOCAL")

    def exec_cmd(self, command, show_rc=False):
        """Executes shell command locally."""
        try:
            self.logger.debug("CMD: %s", command)
            output = check_output(command, stderr=PIPE, shell=True)
        except CalledProcessError as e:
            output = e.returncode, e.message
        except OSError:
            raise CmdFailed(command, 127)
        else:
            output = 0, output
        return output if show_rc else output[1]

    def exec_file_copy(self, source_file, destination=None):
        """Local file copy."""
        destination = destination or "."
        if "*" in os.path.basename(source_file):
            source_file, = glob.glob(source_file)
        if os.path.exists(source_file):
            command = "\cp {} {}".format(source_file, destination)
            self.exec_cmd(command)
        else:
            raise OSError(source_file)


class SshConnector(ConnectorBase):
    """SSH paramiko wrapper class."""
    def __init__(self, ip_address, username, password, retry_count=3):
        self.logger = logging.getLogger("Connector.SSH")
        self.ip = ip_address
        self.user = username
        self.password = password
        self.retries = retry_count
        self.connector, self.connection_status = self._connect()

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
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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

    def exec_file_copy(self, source_file, destination=None):
        """Copy local file to remote target."""
        if "*" in os.path.basename(source_file):
            source_file, = glob.glob(source_file)
        if os.path.exists(source_file) and os.path.isfile(source_file):
            sftp = self.connector.open_sftp()
            if os.path.isabs(destination):
                file_remote = os.path.join(destination, os.path.basename(source_file))
                sftp.put(source_file, file_remote)
                sftp.close()
            else:
                raise ValueError("{} is not absolute path".format(destination))
        else:
            raise OSError("{} is not file or file is unreachable".format(source_file))

