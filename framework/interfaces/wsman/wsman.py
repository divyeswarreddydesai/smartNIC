#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
"""Python module for initiating and executing commands on Windows targets
via WSAN protocol.

Pre requisites:
  1. Enable Win-RM on Windows target
  (A) winrm set winrm/config/service/auth '@{Basic="true"}'
  (B) winrm set winrm/config/service '@{AllowUnencrypted="true"}'
  (C) netsh advfirewall firewall add rule name="allow remote ws-man access"
            dir=in localport=5985 action=allow protocol=tcp
"""
#pylint: disable=dangerous-default-value,broad-except
#pylint: disable=no-name-in-module

import json
import os
import time
import six

from winrm import Session
try:
  from winrm.exceptions import AuthenticationError
except ImportError: # pragma: no cover
  from winrm.exceptions import WinRMAuthorizationError as AuthenticationError

from framework.lib.nulog import DEBUG, WARN, ERROR
from framework.lib.utils import ping
from framework.lib.utils.generic import strip_empty_fields
from framework.exceptions.interface_error import NuTestWSMANError,\
  NuTestWSMANAuthenticationError

class WSMAN:
  """This is the main class to be used to connect to a remote host via WSMAN
  and execute commands.
  """

  def __init__(self, host, **kwargs):
    """Used to initialize WSMAN connection to a host. .

    Args:
      host (str): The SSH host ip or hostname to connect to.
      kwargs:
        username (str, Optional): Username to login with.
                                  Defaults to 'administrator'.
        password (str, Optional): Password to login with.
                                  Defaults to 'nutanix/4u'
        transport (str, Optional): Transport type to login with.
                                  Defaults to 'plaintext'

    Raises:
      NuTestWSMANError
    """

    # Extract required parameters.
    self._host = host
    self._username = kwargs.get('username', 'administrator')
    self._password = kwargs.get('password', 'nutanix/4u')

    if os.environ.get('USE_NTLM_TRANSPORT'):
      DEBUG("Environment variable: USE_NTLM_TRANSPORT is set. "
            "Using 'ntlm' as transport type.")
      default_transport = 'ntlm'
    else:
      default_transport = 'plaintext'

    self._transport = kwargs.get('transport', default_transport)
    self._session_args = strip_empty_fields({
      'read_timeout_sec': kwargs.pop('read_timeout_sec', None)
    })
    self._session = Session(
      self._host,
      auth=(self._username, self._password),
      transport=self._transport,
      **self._session_args
    )

  def execute(self, command, args=None, powershell=True, retries=3, timeout=60,
              log_response=True):
    """Use this routine to execute a command over WSMAN on the remote host.

    Args:
      command (str): The command to execute.
      args (list): The command argument list.
      powershell (bool, Optional): Flag indicating if the command is a
                                   powershell command or not. Defaults to True.
      retries (int, Optional): Number of times to retries in case of failure to
                               execute the command.
                               Defaults to 3.
      timeout (timeout, Optional): Maximum time for the command to complete.
                                   Defaults to 60 seconds.
      log_response (bool, Optional): Logs response if True, else doesn't.
                                     Defaults to True.

    Returns:
      dict: Dict of status, output and stderr

            Example of output for each element in the list:
              {'status': 0, 'output': u'NTNX-13AM3K010073-1-CVM\n','stderr': ''}
              A status for 0 means successful execution of the command.

    """
    if not args:
      args = []
    attempt = 1
    while attempt <= retries:
      DEBUG("%s>> '%s %s', timeout: %d. Attempt: %s" % (self._host, command,
                                                        args, timeout, attempt))
      try:
        if powershell:
          resp = self._session.run_ps(command)
        else:
          resp = self._session.run_cmd(command, args)
        response = {
          'status': resp.status_code,
          'stdout': six.ensure_text(resp.std_out, encoding='utf-8'),
          'stderr': six.ensure_text(resp.std_err, encoding='utf-8')
        }
        if log_response:
          DEBUG("%s<< '%s'" % (self._host, prettify(response)))
        return response
      except AuthenticationError as err:
        ERROR("Authentication Error. Credentials Used : %s,%s" %
              (self._username, self._password))
        raise NuTestWSMANAuthenticationError(
          "Failed to login to target machine. %s" % str(err))
      except Exception as err:
        WARN("Exception : %s" % repr(err))

        if attempt == retries:
          raise NuTestWSMANError("Unable to execute the command",
                                 WSMANCollector(self._host))

        if str(err) == "Bad HTTP response returned from server. Code 400":
          # It is possible the session ID is now not acceptable by
          # the Server as Windows or some setting has started
          # detecting stale requests, we retry with a new session ID.
          DEBUG("Retrying with new session")
          self._session = Session(
            self._host,
            auth=(self._username, self._password),
            transport=self._transport,
            **self._session_args
          )

      attempt += 1
      time.sleep(5)

  def transfer_from(self, remote_path, local_path, retries=3, timeout=360):
    """Transfers a file from remote server

    Args:
      remote_path (str): Remote path of the file to be transferred.
      local_path (str): Local path of the file to be copied.
      retries(int, optional): The number of retries. Defaults to 3.
      timeout(int, optional): Timeout seconds. Defaults to 360.

    Raises:
      NotImplementedError
    """
    raise NotImplementedError

  def transfer_to(self, local_path, remote_path, retries=3, timeout=360):
    """Transfers a local file to remote server

    Args:
      local_path (str): Local path of the file to be transferred.
      remote_path (str): Remote path of the file.
      retries(int, optional): The number of retries. Defaults to 3.
      timeout(int, optional): Timeout seconds. Defaults to 360.

    Raises:
      NotImplementedError
    """
    raise NotImplementedError

class WSMANCollector:
  """This is the log collector for this module"""

  def __init__(self, host=None):
    """Constructor for the log collector class.

    Args:
      host (str): Host name or IP.
    """
    self._host = host

  def collect(self):
    """Implements the collection of ping traces.
    """
    if self._host:
      ping(self._host, use_nmap=True)

def prettify(response):
  """Prettify the response for the debug messages.

    Args:
      response (dict or string): SSH command response.

    Returns:
      output (str): Prettified output
  """

  output = response.copy()
  try:
    output['stdout'] = json.loads(output['stdout'])
  except ValueError:
    pass
  return json.dumps(output, indent=2, ensure_ascii=False)
