"""This Module provides API for  common Linux operations.
Copyright (c) 2015 Nutanix Inc. All rights reserved.

Author: digvija.dalapat@nutanix.com
        sumanth.ananthu@nutanix.com
"""
# pylint:disable=invalid-name,no-member,too-many-public-methods
# pylint:disable=maybe-no-member,unused-argument,too-many-locals
# pylint:disable=arguments-differ,protected-access, no-else-return
# pylint:disable=too-many-lines, no-else-raise, import-outside-toplevel
# pylint:disable=inconsistent-return-statements, try-except-raise,no-else-continue
# pylint:disable=consider-using-enumerate, wrong-import-order, c-extension-no-member, no-else-break

import glob
import math
import os
import re
import subprocess
import tempfile
import time
from framework.vm_helpers.lib.manage_keys import ManageKeys
from framework.vm_helpers.ssh_client import SSHClient
from framework.logging.error import ExpError
# from framework.exceptions.nutest_error import ExpError
# from framework.exceptions.nutest_value_error import ExpError
from framework.interfaces.consts import SVM_USER, SVM_PASSWORD, ClusterCreds
# from framework.interfaces.ssh.ssh import SSH
from framework.lib.consts import CPUArchitecture
# from framework.lib.decorators import retry
from framework.lib.disk_perf import DiskPerfCommandGenerator
# from framework.lib.error_categorisation import ErrorCategory
from framework.logging.log import ERROR, DEBUG, WARN, INFO
from framework.vm_helpers.os_utils import (validate_download, is_ipv6_address,
                                 get_highest_python_version)
from framework.vm_helpers.file_path import FilePath
from framework.vm_helpers.os_consts import \
  YUM_REPO_URLS
from framework.vm_helpers.abstract_os \
  import AbstractOperatingSystem
from framework.vm_helpers.os_consts import IOTools
NUTEST_PATH = os.environ.get("NUTEST_PATH")
from framework.lib.decorators import retry

class LinuxOperatingSystem(AbstractOperatingSystem):
  """
  This class has common LinuxOS operations.
  """
  PACKAGES_IN_LOCAL_REPO = ["nfs-utils", "iscsi-initiator-utils",
                            "open-vm-tools", "epel-release", "lsof",
                            "bzip2", "psmisc"]
  SVM_YUM_REPO_PATH = "/etc/yum.repos.d/"

  def __init__(self, ip='127.0.0.1', username=SVM_USER, password=SVM_PASSWORD,
               pvt_key_path=None,
               allow_agent=True, look_for_keys=True,
               max_connection_attempts=4, ssh_port=22, max_connections=10,
               max_interactive_conn=3, proxy=None,
               proxy_key=None, proxy_port=22,
               pvt_key=None, **kwargs): # pylint: disable=unused-argument
    """This method is used to instantiate the class. This will populate
    several object variables.
    Args:
      kwargs
       ip(str): IP address of the host to execute commands on.
       username(str,optional): Authentication credentials.
         Default: nutanix
       password(str,optional): Authentication credentials.
         Default: nutanix/4u
       pvt_key_path(str,optional):Path to private SSH key.
         Default: None
       allow_agent(bool, Optional): Whether or not to connect to ssh agent
                                    Defaults to True.
       look_for_keys(bool, Optional): Whether or not to look for key files
                                      in ~/.ssh/ Defaults to True.
       max_connection_attempts(int, Optional): Max no.of connection attempts
          that can be attempted to establish a ssh connection.
          Authentication, timeout and network not reachable errors will not be
          exempted under this.
          Default: 3
      ssh_port (int, Optional): Port to use for SSH login. Defaults to 22.
      max_connections (int): Maximum SSH connection allowed.
        Default: 10
      max_interactive_conn (int): Maximum interactive
        SSH connection allowed.
        Default: 3
      proxy (str, Optional): Proxy host to connect to server.
      proxy_port (int, Optional): Port to login to. Defaults to 22.
      proxy_key (str, optional): the key to be used for proxy
      pvt_key(paramiko.key): Private key object.

    Returns:
      (obj): Instance of the class LinuxOperatingSystem.

    Raises:
      1) ValueError
    """
    self._ip = ip
    self._username = username
    self._password = password
    self._allow_agent = allow_agent
    self._look_for_keys = look_for_keys
    self._pvt_key = pvt_key
    self._pvt_key_path = pvt_key_path
    self._local_vm = False
    self._max_connection_attempts = max_connection_attempts
    self._ssh_port = ssh_port
    self._max_connections = max_connections
    self._max_interactive_conn = max_interactive_conn
    self._proxy = proxy
    self._proxy_key = proxy_key
    self._proxy_port = proxy_port
    # INFO(self._username)
    # INFO(self._password)
    if callable(self._pvt_key_path):
      self._pvt_key_path = self._pvt_key_path()
    if callable(self._pvt_key):
      self._pvt_key = self._pvt_key()

    if self._ip == "localhost" or self._ip == "127.0.0.1":
      self._local_vm = True
      self._ssh = None
    else:
      self._ssh = SSHClient(self._ip, username=self._username,
                      password=self._password, key_filename=self._pvt_key_path,
                      allow_agent=self._allow_agent,
                      look_for_keys=self._look_for_keys,
                      max_connection_attempts=self._max_connection_attempts,
                      port=self._ssh_port,
                      proxy=self._proxy,
                      proxy_key=self._proxy_key,
                      proxy_port=self._proxy_port,
                      pkey=self._pvt_key)
    self.interactive_channels = {}
  def parse_stdout_to_dict(self,stdout):
    """
    Parse the stdout string into a dictionary.
    """
    entries = []
    current_entry = {}
    
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            if current_entry:
                entries.append(current_entry)
                current_entry = {}
            continue
        
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            current_entry[key] = value
    
    if current_entry:
        entries.append(current_entry)
    
    return entries
  @property
  def ip(self):
    """Property that returns the IP of machine.

    Args:
      None

    Returns:
      str: IP of the OS.

    Raises:
      None
    """
    return self._ip

  @ip.setter
  def ip(self, ip):
    """Property that sets the IP of a machine.

    Args:
      ip(str): IP to be set as the instance attribute.

    Returns:
      None

    Raises:
      None
    """
    if not ip == self._ip:
      DEBUG("Setting IP: %s" % ip)
      self._ip = ip
      if self._ip == "localhost" or self._ip == "127.0.0.1":
        self._local_vm = True
      else:
        self._local_vm = False
        self._ssh = SSHClient(self._ip, username=self._username,
                        password=self._password, key_file=self._pvt_key_path,
                        allow_agent=self._allow_agent,
                        look_for_keys=self._look_for_keys,
                        max_connection_attempts=self._max_connection_attempts,
                        port=self._ssh_port)

  @property
  def memory(self):
    """Gets the memory size of the VM in GB.

    Returns:
      int: Memory size of the VM in GB.
    """
    cmd = "cat /proc/meminfo"
    result = self.execute(cmd)
    matched = re.search(r'^MemTotal:\s+(\d+)', result["stdout"])
    if not matched:
      return 0
    mem_total_kb = int(matched.groups()[0])
    mem_total_gb = int(math.ceil(mem_total_kb / (1024.0 * 1024.0)))
    return mem_total_gb

  @staticmethod
  def local_execute(cmd):
    """Method to executes a command on local machine.

    Args:
      cmd(str): Command to be executed.
    Returns:
      (dict): With keys "status" and "output" of the command execution.

    Raises:
      None
    """
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True,
                         close_fds=True, encoding='utf-8',
                         stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    response = {'status': p.returncode,
                'stdout': stdout,
                'stderr': stderr}
    DEBUG("localhost <<: %s" % response)
    return response
  def start_iperf_server(self,udp_protocol=False):
        """
        Start the iperf server on the remote VM.
        """
        try:
            if udp_protocol:
                server_command = "sudo iperf3 -s -D "
            else:
                server_command = "sudo iperf3 -s -D "
            
            for loop in range(1, 6):
              result = self.execute(server_command,background=True)
              time.sleep(3)
              # self.execute("ifconfig")
              response = self.execute("ps -ef | grep iperf3")['stdout']
              if "iperf3 -s -D" in response:
                break

              if loop == 5:
                ERROR("Unable start iperf server")
                raise ExpError("Unable start iperf server")

              INFO("Try(%s/5): Starting iperf3 server failed. Try again" % loop)
            # if result['status'] == 0:
                # INFO("iperf server started successfully.")
                # INFO(f"iperf server output: {result['stdout']}")
            # else:
            #     ERROR(f"Failed to start iperf server: {result['stderr']}")
            #     raise ExpError(f"Failed to start iperf server: {result['stderr']}")
    
            INFO("iperf server started successfully.")
        except ExpError as e:
            ERROR(f"Failed to start iperf server: {e}")
            raise ExpError(f"Failed to start iperf server: {e}")
  # @retry(retries=3, sleep_interval=5)
  def run_iperf_client(self, server_ip,udp_protocol, duration=10, parallel=1):
        """
        Run the iperf client on the remote VM.
        Args:
        server_ip(str): IP address of the iperf server
        duration(int): Duration of the test in seconds
        parallel(int): Number of parallel streams
        """
        try:
            if udp_protocol:
                client_command = f"sudo iperf3 -c {server_ip} -t {duration} -P {parallel} -i 1 -b 10G -u"
            else:
                client_command = f"sudo iperf3 -c {server_ip} -t {duration} -P {parallel} -i 1"
            result = self.execute(client_command)
            INFO("iperf client ran successfully.")
            # INFO(result['stdout'])
            return result['stdout']
        except ExpError as e:
            ERROR(f"Failed to run iperf client: {e}")
            raise ExpError(f"Failed to run iperf client: {e}")
  @staticmethod
  def local_interactive_execute(cmd, prompt=''):
    """Method to executes an interactive command on local machine.

    Args:
      cmd(str): Command to be executed.
      prompt(str, optional): Prompt to be sent to the command.

    Returns:
      (dict): With keys "status" and "output" of the command execution.

    Raises:
      None
    """
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, shell=True,
                         close_fds=True, encoding='utf-8',
                         stderr=subprocess.PIPE)
    p.stdin.write(prompt)
    stdout, stderr = p.communicate()
    p.stdin.close()
    response = {'status': p.returncode,
                'stdout': stdout,
                'stderr': stderr}
    DEBUG("localhost <<: %s" % response)
    return response

  def change_user_credentials(self, username, password):
    """
    Set the username/password for the ssh connection

    Args:
      username (str): username
      password (str): password
    """
    self._username = username
    self._password = password
    if self._ssh:
      self._ssh.close()
    self._ssh = SSHClient(self._ip, username=self._username,
                    password=self._password, key_file=self._pvt_key_path,
                    allow_agent=self._allow_agent,
                    look_for_keys=self._look_for_keys, port=self._ssh_port)

  def collect(self):
    """Method which collects details in case of a failure.

    Args:
      None.

    Args:
      None.
    """
    self.execute("tail -100 /var/log/dmesg", ignore_errors=True)

  def download_file(self, url, local_path, timeout=600, retries=3,
                    retry_interval=60, untar=False, untar_dir=None,
                    untar_timeout=1800, **kw_options):
    """Method to download a file from remote HTTP location.

    Args:
      url(str): URL location for download the file from.
      local_path(str): Absolute local path to save file to.
      timeout(int,optional): Wait time in seconds, after which the operation
        will be aborted.
        Default: 600 seconds.
      retries(int, optional): Number of retries for the wget command to succeed.
        Default: 3.
      retry_interval(int, optional): Sleep interval between retries. Default:
        60 seconds.
      untar(bool,optional): A boolean to decide untaring the downloaded file.
        Default: False
      untar_dir (str, optional): Directory location where files will be
        untarred. Default: local_path.
      untar_timeout (int, optional): Wait time in seconds for untar to complete.
        Default: 1800 seconds.
      kw_options (dict, optional): Keyword options fo wget.

    Returns:
      bool: True on successful download. Raises exception otherwise.

    Raises:
      1) ExpError.

    Notes:
      1) This routine doesn't return False on Failure download. Instead,
        it will raise the exception.
    """
    download_success = self._download_file(url, local_path, timeout=timeout,
                                           retries=retries,
                                           retry_interval=retry_interval,
                                           **kw_options)
    if not download_success:
      raise ExpError("Failed to download file from %s" % url)

    if os.environ.get('JITA_CLOUD_AGENT_RUN') == "1" and \
                                    not url.endswith('.sha256'):
      download_success = self._download_file(url+'.sha256',
                                             local_path+'.sha256', retries=3)
      if not download_success:
        raise ExpError(
          "Failed to download %s.sha256 for validation" % url)

      validate_download(self, url, local_path, True)

    if untar:
      if not untar_dir:
        untar_dir = "/".join(local_path.split("/")[0:-1])
      self.untar_file(local_path, untar_dir, timeout=untar_timeout)
    return True

  def download_ovftool(self, ovf_tool_url=None, target=None):
    """
    Download vmware-ovftool and extract it.
    Args:
      ovf_tool_url(str): url containing the ovf tool location.
      target(str): target location to download the ovf tool.
    Returns:
      (bool) True on success, else False.
    """
    OVFTOOL_LOC = "/tmp/ovftool"
    if not ovf_tool_url:
      ERROR("OVF tool url to download the file from cannot be empty.")
      return False

    if not target:
      ERROR("Target location to download the ovf tool from cannot be empty.")
      return False

    if not self.download_file(ovf_tool_url, target, untar=False):
      ERROR("Failed to download ovf tool on host %s" % self)
      return False

    DEBUG("Extract the ovftool from target %s." % target)
    cmd = "if [ -d %s ]; then rm -rf %s; fi; "\
            % (OVFTOOL_LOC, OVFTOOL_LOC)
    cmd += "sudo mount -o remount,exec /tmp && "
    cmd += "bash %s --extract=%s --eulas-agreed && "\
            % (target, OVFTOOL_LOC)
    cmd += "sudo mount -o remount,noexec /tmp && "
    cmd += "chmod +x %s/vmware-ovftool/ovftool*" % OVFTOOL_LOC

    result = self.execute(cmd, timeout=300)
    if result['status'] != 0:
      ERROR("Command %s failed: rv: %s, stdout: %s, stderr:%s"
            % (cmd, result['status'], result['stdout'], result['stderr']))
      return False
    return True

  def execute(self, cmd, timeout=60, retries=3, ignore_errors=False,
              poll_interval=5, tty=None, run_as_root=False,
              retry_on_regex=None, background=False, log_response=True,
              trailing_sleep=False, conn_acquire_timeout=360,
              close_ssh_connection=False, disable_safe_rm=True,
              log_command=True, async_=False, session_timeout=10):
    """Method to execute the specified command on the OS.

    Args:
      cmd (str): Command to execute.
      timeout(int, optional): wait time in seconds for the command execution.
        Default: 60 seconds.
      retries(int, optional): Maximum Number of attempts to successfully
        execute command. Applicable for connecion issues only.
        Successful execution of command implies sending the command to shell
        and receiving a response back. The command is not 'retried' if the
        command exits with a non-zero status code.
        Default: 1
      ignore_errors (bool or callable): Whether or not to ignore command
        execution errors. It does not include connection errors. This can also
        be a callable that takes one argument, and returns a bool. The argument
        corresponds to the command execution result, and the return value would
        be whether or not to ignore the error.
        Default: False
      poll_interval(int, optional): Sleep period after which a command execution
        is retried. Default: 5 seconds.
      tty (bool, optional): If a TTY should be used on not. Defaults to True.
      run_as_root (bool, optional): If True, run the command as root (use sudo).
      retry_on_regex(regex): Retry command if output matches regex.
      background(bool, Optional): conveys if it's a background command
                            execution or not and that we should wait for
                            stderr and stdout or not.
                            Default: False (wait for stderr and stdout)
                            If this is enabled, after sending the command,
                            we will wait and read status but for stderr and
                            stdout, we will just attempt to read as long the
                            data is available to read.
                            This behavior helps to gather any errors logged,
                            if the command has failed. But if your command
                            emits stdout or stderr continuously, you should
                            ensure to redirect stdout, stderr appropriately,
                            otherwise this attempt to read stdout/stderr will
                            still block you.
                            NOTE: We will append '&' to background the
                            command execution. tty option need not be provided.
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False.
      trailing_sleep (bool, Optional): Whether a sleep is required for a
                                       command execution.
                                       NOTE: This is present only for
                                       workarounds when background sudo commands
                                       don't get executed. Default: False
      conn_acquire_timeout (timeout, Optional): Maximum time to acquire/create
                            a connection.
                            Defaults to 360 seconds.
      close_ssh_connection (bool, Optional): Flag to set whether to close the
                                    SSH connection used for command execution.
                                    False by default.
      disable_safe_rm (bool, Optional): Whether to disable safe rm or not.
                                        Defaults to True.
      log_command (bool, Optional): Whether to log the command passed. Would
                                    be used while running commands including
                                    passwords. Defaults to True.
      async_ (bool, Optional): Flag to specify
       if ssh command execution should be asynchronous.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.
    Returns:
      dict: With keys "status", "stdout" and "stderr" of the command execution

    Raises:
      ExpError
    """
    attempts = 0
    result = {}
    if background:
      cmd += ' &'
      if trailing_sleep:
        cmd += ' sleep 1'
    if tty is None:
      if background:
        # dont use tty so that we are not blocked by processes attached to
        # the terminal.
        tty = False
      else:
        # we normally use tty=True (in line with ssh.py execute())
        tty = True
    while attempts < retries:
      result = self.__execute(cmd=cmd, retries=retries, timeout=timeout,
                              tty=tty, run_as_root=run_as_root,
                              background=background, log_response=log_response,
                              conn_acquire_timeout=conn_acquire_timeout,
                              close_ssh_connection=close_ssh_connection,
                              disable_safe_rm=disable_safe_rm,
                              log_command=log_command, async_=async_,
                              session_timeout=session_timeout)
      # If ignore_errors is a bool, check if it is True.
      # If ignore_errors is a callable, evaluate it with the result and check.
      if async_:
        return result
      if (isinstance(ignore_errors, bool) and ignore_errors
          or callable(ignore_errors) and ignore_errors(result)):
        return result
      # INFO(result)
      # Did we get a non-zero return status ?
      attempts += 1
      if result['status']:
        if re.search(r"Too many logins for", result['stdout']):
          WARN("Unavailable sessions to %s. Retrying..." % self._ip)
        elif re.search(r"Last login: ", result['stdout']):
          WARN("Unable to get command output on '%s'. Retrying..." % self._ip)
          ## Clearing older connections before retry.
          if self._ssh:
            self._ssh.close()
        else:
          # If we received a non-zero return in any other case, then raise
          # exception.
          break
      else:
        if (retry_on_regex and
            bool(re.search(retry_on_regex, result["stdout"]))):
          WARN("Retrying.Unexpected command output: %s..." % result["stdout"])
        else:
          return result

      time.sleep(poll_interval)
    if attempts >= retries:
      WARN("Exhausted retries to execute '%s' command on '%s'." % (cmd,
                                                                   self._ip))
    exc = ExpError("Command: %s. Result %s" % (cmd, result))
    exc.command = cmd
    exc.result = result
    raise exc

  def get_interactive_channel(self, retries=3):
    """Get an interactive ssh channel.

    Args:
      retries(integer): Number of retries in case of NuTestSSHChannelError.

    Returns:
      object: The channel object.

    Raises:
      NuTestSSHChannelError: When failed to get interactive channel after
                      all retries.
    """
    for _ in range(0, retries):
      ssh_client = self._ssh.get_interactive_connection()
      try:
        chan = self._ssh.get_interactive_channel(ssh_client)
        self.interactive_channels[chan] = ssh_client
        return chan
      except ExpError as exc:
        # Create a new channel if channel failure msgs are found
        DEBUG("Hit error while trying to get interactive channel: %s"
              "A new connection will be attempted" % str(exc))
        self._ssh.close_interactive_connection(ssh_client)
        time.sleep(1)
      except ExpError:
        self._ssh.close_interactive_connection(ssh_client)
        raise
    raise ExpError("Failed to get interactive channel")

  # pylint: disable=broad-except
  def close_interactive_channel(self, channel):
    """Close the interactive active and release its corresponding
    ssh client handle.

    Args:
      channel (object): Channel object.
    """
    try:
      self.interactive_channels.get(channel)._transport.close()
      # channel.close()
    except Exception:
      # Best effort closure.
      pass

    self._ssh.release_interactive_connection(
      self.interactive_channels.pop(channel))

  def send_to_interactive_channel(self, command, interactive_channel,
                                  timeout=30, disable_safe_rm=True,
                                  log_command=True):
    """Send command to an interactive SSH channel on the remote host.

    Args:
      command (str): The command to execute.
      interactive_channel (object): The interactive channel to execute the
                            command upon
      timeout (timeout, Optional): Maximum time for the command to be sent
                                   Defaults to 30 seconds.
      disable_safe_rm (bool, Optional): Whether to disable safe rm or not.
                                        Defaults to True.
      log_command (bool, Optional): Whether to log the command passed. Would
                                    be used while running commands including
                                    passwords. Defaults to True.

    Returns:
      None
    """
    if disable_safe_rm:
      command = self.__handle_safe_rm(command)
    self._ssh.send_to_interactive_channel(
      command=command, interactive_channel=interactive_channel,
      timeout=timeout, line_separator="\n", log_command=log_command)

  def receive_from_interactive_channel(self, interactive_channel):
    """Receive response from an interactive SSH channel on the remote host.

    Args:
      interactive_channel (object): The interactive channel to read the
                            response from
    Returns:
      str: response from the channel
    """
    return self._ssh.receive_from_interactive_channel(
      interactive_channel=interactive_channel)

  def execute_on_interactive_channel(self, command, interactive_channel,
                                     pattern, timeout=30,
                                     re_flags=0, disable_safe_rm=True):
    """Execute command over an interactive SSH channel on the remote host.

    Args:
      command (str): The command to execute.
      interactive_channel (object): The interactive channel to execute the
                            command upon
      pattern (str): Regular expression to be matched in the received response
      timeout (timeout, Optional): Maximum wait time for the pattern to match
                            between command sent and response received
                            Defaults to 30 seconds.
      re_flags (integer, Optional): Python standard regular expression flags
      disable_safe_rm (bool, Optional): Whether to disable safe rm or not.
                                        Defaults to True.

    Returns:
      object: iterator over all non-overlapping matches for the regular
           expression pattern in the response
    """
    if disable_safe_rm:
      command = self.__handle_safe_rm(command)
    return self._ssh.execute_on_interactive_channel(
      command=command, interactive_channel=interactive_channel,
      pattern=pattern, timeout=timeout, line_separator="\n",
      re_flags=re_flags)

  def execute_on_interactive_channel_pwd(self, command,
                                         interactive_channel,
                                         password="nutanix/4u",
                                         timeout=30, line_separator="\n",
                                         pwd_retry_message="try again",
                                         pwd_retry=3, pwd_entry_interval=5,
                                         response_wait_interval=15,
                                         disable_safe_rm=True):
    """Execute command over an interactive SSH channel on the remote host
       along with passing password on prompt for sudo commands.

    Args:
      command (str): The command to execute.
      interactive_channel (object): The interactive channel to execute the
                            command upon
      password (str): password to enter interactively on prompt.
      timeout (timeout, Optional): Maximum wait time for the pattern to match
                            between command sent and response received
                            Defaults to 30 seconds.
      line_separator (str, Optional): line separator character
                            (equivalent of pressing Enter button for command)
                            For Windows, it is \r\n.
      pwd_retry_message (str, Optional): str to be checked for retry of
                                         password.
                                         Defaults to "try again".
      pwd_retry (int): number of retries for password entry.
                   Defaults to 3.
      pwd_entry_interval (int): wait interval between password entries.
                                Defaults to 5 sec.
      response_wait_interval (int): sleep time before getting response after
                                    password entry. Defaults to 15 sec.
      disable_safe_rm (bool, Optional): Whether to disable safe rm or not.
                                        Defaults to True.

    Returns:
      dict: response from interactive channel.

    Raises:
      ExpError
    """
    if disable_safe_rm:
      command = self.__handle_safe_rm(command)

    try:
      response = ""
      self._ssh.send_to_interactive_channel(
        command=command, interactive_channel=interactive_channel,
        timeout=timeout, line_separator=line_separator)
      while pwd_retry > 0:
        time.sleep(pwd_entry_interval)
        DEBUG("Passing <password> on prompt")
        self._ssh.send_to_interactive_channel(
          '%s\n' % password, interactive_channel, log_command=False)
        time.sleep(response_wait_interval)
        response = self._ssh.receive_from_interactive_channel(
          interactive_channel=interactive_channel)
        if pwd_retry_message not in response:
          DEBUG("Command executed.Response {}".format(response))
          return response
        pwd_retry -= 1
      raise ExpError("Failed due to password entry "
                                        "failure. Response: '{response}'"
                                        .format(response=response))
    except Exception as e:
      raise ExpError("Error while executing interactive "
                                        "command:{error}, Response:'{response}'"
                                        .format(error=e, response=response))

  def exists(self, file_path, **kwargs):
    """This method is used to check if a path exists a directory.

    Args:
      file_path(str): Path of a direcotry or file.
      **kwargs: Arguments to be passed to execute method

    Returns:
      (bool): True if path exists, False otherwise.
    """
    cmd = "test -e '%s'" %file_path
    result = self.execute(cmd=cmd, ignore_errors=True, **kwargs)
    if result["status"]:
      return False
    else:
      return True

  @retry(retries=3, sleep_interval=5)
  def get_checksum(self, path_list, **kwargs):
    """Method to get checksum of file(s).

    Args:
      path_list(list): List of paths for which checksum needed.
      kwargs:
       cksum_type(str, optional): Type of checksum to be used.
        Default: 'md5'
       sudo(bool, optional): Runs the command as sudo.
        Default: False.
       Any additional parameter to be sent to self.execute.

    Returns:
      str: Checksum calculated.

    Raises:
      ExpError.

    Notes:
      To use sudo, the machine should have set NOPASSWD for the user, else this
      will wait for password from standard input.
    """
    cksum_type = kwargs.pop("cksum_type", "md5")
    sudo = kwargs.pop("sudo", False)
    checksum_path = {"md5" : "md5sum",
                     "sha256": "sha256sum",
                     "sha512": "sha512sum"}
    checksum_list = []
    for path in path_list:
      cmd = "%s '%s'" % (checksum_path[cksum_type], path)
      if sudo:
        cmd = "sudo %s" % cmd
      result = self.execute(cmd, **kwargs)
      if result['status']:
        raise ExpError("Failed to executed command : %s" %
                                          cmd)
      # In case there are any additional lines in stdout (e.g. DIAL-4966),
      # we'll filter on only the line that contains the filepath.
      cksum = [line.split()[0] for line in result['stdout'].splitlines() if
               path in line][0]
      cksum = str(cksum).strip()
      checksum_list.append(cksum)
      DEBUG("Checksum computed for file %s is %s" % (path, cksum))

    return checksum_list

  def get_disk_perf_path(self):
    """Method to get the 'disk_perf's binary path.

    Returns:
      str: path of disk perf binary

    Raises:
      ExpError: When 'disk_perf' binary is not installed.
    """
    cmd = "which disk_perf"
    result = self.execute(cmd=cmd)
    if not result['status']:
      path = result['stdout']
      DEBUG("disk perf binary path: %s" % (result['stdout']))
    else:
      raise ExpError("disk_perf binary may be not installed: %s" %
                             result['stdout']
                            )
    return path

  def get_interface_ip(self, interface, suppress=False):
    """Get the IP of the interface on the machine if the interface is up.

    Args:
      interface(str): Interface of the machine to get IP for.
      suppress (boolean): Boolean to suppress exception if IP is not found.
                          (Returns None in that case)
    Returns:
      str: IP if interface is up and running.

    Raises:
      ExpError: If unable to get IP for interface
    """
    eth_interface_ip_cmd = "/sbin/ifconfig %s" % interface
    result = self.execute(eth_interface_ip_cmd)
    if result['status'] and not suppress:
      raise ExpError("Unable to get IP for %s for interface:"
                                        " %s" % (self._ip, interface))

    if not result['stdout'] and not suppress:
      raise ExpError("Interface:%s does not exist for: %s"
                                        % (interface, self._ip))
    if not re.search("UP.BROADCAST.RUNNING", result['stdout']) and not suppress:
      raise ExpError("Interface:%s is not up for NVM: %s"
                                        % (interface, self._ip))
    match = re.search(r"inet (addr:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                      result["stdout"])
    if not match and not suppress:
      raise ExpError("Interface:%s is missing IP for NVM: "
                                        "%s" % (interface, self._ip))
    elif match:
      ip = match.group(2)
      DEBUG('IP Found: %s' % ip)
      return ip
    else:
      return None

  def get_mount_path(self, remote_ip, ctr_name):
    """This routine is used to check if a container is mounted on a machine or
    not.

    Args:
      remote_ip (str): Remote IP to which the mount point is created.
      ctr_name (str): Name of the container.

    Returns:
      str: Mount path of ctr_name if it is mounted, None otherwise.

    Raises:
      ExpError: When 'ctr_name' isn't valid.
    """
    DEBUG("Fetching container mount point for %s" % ctr_name)
    if not ctr_name:
      raise ExpError("Invalid container name")
    try:
      result = self.execute(
        "mount | grep -e '^%s:/%s'" % (remote_ip, ctr_name))
      line = str(result["stdout"])
      return line.split()[2]
    except ExpError:

      # Case where ctr is not mounted.
      return None

  def get_nameservers(self):
    """Gets the list of name servers for Linux UVM.

    Returns:
      list: The list of name servers configured on the Linux UVM.
    """
    cmd = "grep -i nameserver /etc/resolv.conf"
    DEBUG("Getting the list of name servers on the uvm")
    out = self.execute(cmd)
    nameservers = out["stdout"].strip().split("\n")
    nameserver_ip_list = []
    for i in range(0, len(nameservers)):
      nameserver_ip_list.append(nameservers[i].split(' ')[1].strip())

    return nameserver_ip_list

#   def add_host_resolution_ip(self, name, ip, change_permission=False):
#     """Add a host name and IP to the machine's name resolution.

#     Args:
#       name (str): Name of the host to add the resolution IP of.
#       ip (str): IP address to add.
#       change_permission (bool): Change the permission of
#                                 /etc/hosts file to 644.
#     """
#     from framework.entities.manage_ip import ManageIPs
#     if not (os.environ.get("NUTEST_TELEPORT_CLUSTER", None) and
#             ManageIPs.is_hyperv_or_svm_ip(self._ip)):
#       with tempfile.NamedTemporaryFile() as fileobj:
#         etc_hosts_path = "/etc/hosts"
#         self.transfer_from(etc_hosts_path, local_path=fileobj.name)
#         lines = fileobj.readlines()
#         for line in lines:
#           line = line.decode()
#           if name in line:
#             DEBUG("Host resolution IP %s for %s already set in SVM %s"
#                   % (line.split()[0], name, self.ip))
#             break
#         else:
#           addendum = "%s %s\n\n" % (ip, name)
#           fileobj.write(addendum.encode())
#           fileobj.seek(0)
#           temp_remote_path = "/tmp/hosts"
#           self.transfer_fileobj_to(fileobj, remote_path=temp_remote_path)
#           self.execute("mv %s %s" % (temp_remote_path, etc_hosts_path),
#                        run_as_root=True)
#           if change_permission:
#             self.execute("chmod 644 %s" % etc_hosts_path, run_as_root=True)
#     else:
#       cmd = '! grep -i %s /etc/hosts && sudo chmod 666 /etc/hosts && ' \
#             'echo "%s %s" | sudo tee -a /etc/hosts && sudo chmod 644 /etc/hosts'
#       result = self.execute(cmd % (name, ip, name), ignore_errors=True)
#       if result['status'] != 0:
#         if name not in result["stdout"]:
#           ERROR("Configuring filer name %s on %s failed with status:%s,"
#                 " stdout:%s stderr:%s" % (name, self.ip, result["status"],
#                                           result["stdout"], result["stderr"]))
#         else:
#           DEBUG("Host resolution name %s is already configured on %s"
#                 % (name, self.ip))
#       else:
#         DEBUG("Configured filer name %s successfully on %s" % (name, self.ip))


  def install(self, package_name, use_fallbacks=True, releasever=None,
              architecture=CPUArchitecture.X86, force_install=False,
              cache_cleanup=False):
    """Method to install a package.

    Args:
      package_name(str): package name to install on local machine.
      use_fallbacks (bool): This specifies whether to install
        from another repo, if default repo fails.
        Default: True
      releasever (str): This specifies the centos repo version to be used
        on fallback.
        Default: "7"
        NOTE: Since Centos 7.3.1611 repo has been reomved, yum install fails.
          They recommend to use 7 repo as fallabck, if needed.
      architecture (CPUArchitecture): CPU Architecture of hypervisor, used to
        fetch corresponding path for yum RPMs.
      force_install (bool): Installing the package even if it is
                            installed already.
        Default: False
      cache_cleanup (bool): Cleanup cache before and after installation.
        Default: False
    Returns:
      None
    """
    try:
      if not force_install:
        cmd = "sudo yum list installed -y %s" % package_name
        result = self.execute(cmd=cmd, ignore_errors=True, timeout=300)
        if result['status'] == 0 and package_name in result['stdout']:
          DEBUG("%s already installed. Skipping Installation" % package_name)
          return
      if cache_cleanup:
        self.cleanup_cache()

      cmd = "sudo yum install -y --nogpgcheck %s " % (package_name)
      self.execute(cmd=cmd, timeout=600)

      if cache_cleanup:
        self.cleanup_cache()
    except (ExpError, ExpError) as exc:
      WARN("%s" % str(exc))
      if use_fallbacks:
        DEBUG("Hit Error with yum install. "
              "Trying fallack options to install: %s" % package_name)
        if releasever is None:
          releasever = self.get_os_version()["major"]
        try:
          releasever = int(releasever)
        except ValueError:
          WARN("Unable to find release version, assuming 7: {}"
               .format(releasever))
          releasever = 7

        return self.__use_fallback_install_options(
          package_name, releasever, architecture)
      raise


  def cleanup_cache(self, ignore_errors=True):
    """
    runs yum clean up to remove cache.
    Args:
      ignore_errors (bool): Whether or not to ignore command
                            execution errors.
                            Default : False
    Returns:
      dict: response from the execution

    """
    cmd = "sudo yum cleanup all"
    return self.execute(cmd=cmd, ignore_errors=ignore_errors)

  def get_os_version(self):
    """Fetch the version of the linux operating system.
    This currently works for RHEL, CentOS, Rocky, todo add support for SuSE
    if that is needed.

    Returns:
      dict: Keys of distro (centos/rhel), major, and minor versions.
            So CentOS 6.5 would be:
              {'distro': 'centos',
               'major': '6',
               'minor': '5'}
    """
    # This info CAN change over the life of the object. Imagine an upgrade
    # from el7 to el8. Since 'cat'ing a file is really fast there isn't really
    # a benefit from caching.
    versions = {"distro": "", "major": "", "minor": ""}
    result = self.execute("cat /etc/redhat-release", ignore_errors=True)
    if not result['status']:
      if "Cent" in result['stdout']:
        versions['distro'] = "centos"
      elif "Red Hat Enterprise" in result['stdout']:
        versions['distro'] = "rhel"
      elif "Rocky" in result['stdout']:
        versions['distro'] = "rocky"

      reg = re.search(r'(\d+)\.(\d+)', result['stdout'])
      if reg:
        versions['major'] = reg.group(1)
        versions['minor'] = reg.group(2)

    self.os_version_details = versions

    return versions

  @retry(return_value=False, retries=3)
  def is_accessible(self, count=3, use_nmap=False, **kwargs):
    """Method to check if the operating system is accesible over a network
    interface.

    Args:
      count(int): The number of times IP should be pinged.
      use_nmap(bool): This specifies whether to use nmap or not.
        Default: False

    Returns:
      bool: True if it is accessible, False otherwise.

    Raises:
      None
    """
    if use_nmap:
      rval = self.check_ssh_port_status()
      if rval is not None:
        return rval
    cmd = "ping -c %s %s" %(count, self._ip)
    if is_ipv6_address(self._ip):
      cmd = "ping -6 -c %s %s" % (count, self._ip)
    try:
      result = self.execute(cmd)
      return result["status"] == 0

    except ExpError as error:
      WARN("Could not ping to %s: %s" %(self._ip, str(error)))
      return False

  def check_ssh_port_status(self, desired_state="open"):
    """ Method to check SSH port status using nmap.
    Args:
      desired_state(str): Desired state for the port['open|closed|filtered']
        Default: "open"
    Returns:
      bool: True if it is correct status, False otherwise.

    Raises:
      ExpError: When failed to execute nmap command or reaches retry limit
                   due to timeout.
    """
    def _execute_nmap_ssh_scan_cmd(ip, timeout, debug=False):
      """
      Executes command to run nmap scan for ssh port
      and returns code and message.
      Args:
        ip (str): target host to run ssh port scan.
        timeout (str): host timeout for exiting the scan.
        debug (bool): scan is run with highest debug level d9.
          Default: False
      Returns:
        tuple: returns a tuple of message and code.

      """
      cmd = "nmap {} -PN -n -sT -p ssh --host-timeout {}".format(ip, timeout)
      if is_ipv6_address(ip):
        cmd = "nmap -6 {} -PN -n -sT -p ssh --host-timeout {}".\
          format(ip, timeout)
      if debug:
        cmd = "%s -d9" % cmd
      DEBUG("Executing command %s" % cmd)
      process = subprocess.Popen(['/bin/sh', '-c', cmd], stdout=subprocess.PIPE,
                                 encoding='utf-8')
      # calling communicate first to set returncode
      return process.communicate()[0], process.returncode

    retry_attempts = 3
    try:
      while retry_attempts > 0:
        stdout, return_code = _execute_nmap_ssh_scan_cmd(self._ip, "30s")
        # If nmap is not present as a system level package we get a
        # return code of 127.
        if return_code == 127:
          return
        if 'host timeout' not in stdout:
          break
        else:
          DEBUG("Attempting retry as SSH port scan timed out.")
          retry_attempts -= 1
          continue

      if retry_attempts == 0:
        WARN("Maximum retry attempts reached due to timeout.")
        raise ExpError("nmap SSH port scan timed out.")
    except Exception:
      WARN("Failed while determining SSH port status using nmap.")
      stdout, return_code = _execute_nmap_ssh_scan_cmd(self._ip, "10s",
                                                       True)
      ERROR("Verbose output for SSH port scan \n%s" % stdout)
      raise

    rval = False
    output = "Status Code: %s, Output: \n%s" % (return_code, stdout)
    if not return_code and (desired_state in stdout):
      rval = True
      DEBUG("SSH Port is in the desired state %s => %s" % (desired_state,
                                                           output))
    else:
      ERROR("SSH Port is not in the desired state %s => %s" % (desired_state,
                                                               output))

    return rval

  def is_graceful_shutdown(self):
    """This method will provide information regarding last shutdown

    Args:
      None

    Returns:
      bool: True if last shutdown was graceful, False otherwise.

    Raises:
      ExpError: When the command *last* returns unexpected output.
    """
    output = self.execute("last -x reboot shutdown")
    output_lines = output['stdout'].split("\r\n")

    # In case when VM is just created and never rebooted before.
    if len(output_lines) < 2:
      return True

    # Expecting the first message to be regarding reboot, since VM is up.
    if not output_lines[0].startswith("reboot"):
      raise ExpError("Unexpected output: %s" % output_lines)

    # If 2nd recent message is shutdown, then that means it was a graceful
    # shutdown.
    return output_lines[1].startswith("shutdown")

  def mkdir(self, dir_path):
    """This method is used to create a directory.If the intermediate directories
    are not present, it will create them too.

    Args:
      dir_path (str): Path of the directory.
    """
    self.execute("mkdir -p %s" % dir_path)

  def modify_yum_repo_to_vault(self):
    """
    Helper method to form command for changing the baseurl

    Returns:
      None

    Raises:
      None:
    """
    try:
      cmd = ("sudo sed -i 's/mirrorlist/#mirrorlist/g' "
             "/etc/yum.repos.d/CentOS-*; sudo sed -i "
             "'s|#baseurl=http://mirror.centos.org|baseurl="
             "http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*")
      self.execute(cmd=cmd)
    except ExpError:
      pass

  def mount(self, remote_ip, remote_path, local_mount_path,
            unmount_on_mismatch=False, timeout=120, **kwargs):
    """Method to mount container. If container is already mounted, then this
    method will take an action depending on the preference given to 'unmount'
    option.

    Args:
      remote_ip(str): remote machine IP for mount.
      remote_path(str): path from the remote machine.
      local_mount_path(str): local path for mount.
      unmount_on_mismatch(bool, optional): This comes into picture only when the
      remote_path is already mounted under some other local path. This is seen
      as a mismatch in specification. If enabled, that some other local path
      will be unmounted, so that the remote_path can be mounted in the user
      specified local_mount_path. If disabled, it will ignore the mismatch and
      simply returns the some other local path where its already mounted.
      Default: False
      timeout(int): The timeout in seconds, for the operation. Default: 120
      kwargs:
        noac (bool): Sets noac flag for sync writes. Default: False.
        nolock (bool): Sets nolock flag to disable file locking. Default: False.

    Returns:
      str: Absolute Path of Container mount point in Linux context.
       eg:-  /tmp/mount_1461484395

    Notes:
      1) remote_path will auto-append "/" if it does not start with "/".
      2) If container is already mounted, then this method utilizes it
         by default. But you can control that behavior using
         unmount_on_mismatch option.
      3) Else, it will create a new directory as provided in local_mount_path,
         and mount the container to it.
    """
    mount_path = None
    remote_path_with_root = None
    if is_ipv6_address(remote_ip):
      remote_ip = "[%s]" % remote_ip
    if remote_path.startswith("/"):
      remote_path_with_root = remote_path
      remote_path = remote_path.split("/")[1]
      mount_path = self.get_mount_path(remote_ip=remote_ip,
                                       ctr_name=remote_path)
    else:
      remote_path_with_root = "".join(["/", remote_path])
      mount_path = self.get_mount_path(remote_ip, remote_path)

    if mount_path and (mount_path != local_mount_path) and unmount_on_mismatch:
      DEBUG("Remote path %s:/%s is already mounted under %s, "
            "unmounting that" % (remote_ip, remote_path, local_mount_path))
      self.unmount(path=mount_path)
      mount_path = None

    # If path is already mounted, return the mounted path
    if not mount_path:
      cmd_list = ["sudo mount -vvv"]
      if kwargs.get("noac", None):
        cmd_list.append("-o noac")
      if kwargs.get("nolock", None):
        cmd_list.append("-o nolock")
      cmd_list.append("%s:%s %s" % (remote_ip, remote_path_with_root,
                                    local_mount_path))
      self.execute("sudo mkdir -p %s" % (local_mount_path), ignore_errors=True)
      cmd = " ".join(cmd_list)
      max_attempts = 3
      for count in range(1, max_attempts+1):
        try:
          self.execute(cmd, timeout=timeout)
          break
        except ExpError:
          if count == max_attempts:
            raise
          time.sleep(3)
      mount_path = local_mount_path
    else:
      DEBUG("Remote path '%s' already mounted at '%s'. Skipping remounting." %
            (remote_path, mount_path))
    return mount_path

  @retry(retries=3, sleep_interval=60)
#   def network_mount(self, network_path, path, username, password, remount=True,
#                     domain_name=None, **kwargs):
#     """
#     Mount a specified path for the first time or unmount and then mount
#     it, if remount is true.

#     Args:
#       network_path(str): The network path to be mounted.
#       path(str): The path to be mounted.
#       username(str): The username to be used for mounting(as specified in AD).
#       password(str): The password for the mentioned username.
#       remount(bool): To unmount first, if the mount path is already in use.
#       domain_name(str): The name of the network domain.
#       kwargs(dict): Keyword Argument might contain DNS IP.
#         verbose(bool, optional): True implies we use -v option.
#         nfs_version(int, optional): Specifies the nfs version to be used.
#         timeout(int, optional): Defaults to 60s
#         linux_mount_options(str, optional): Comma separated string with
#         various mount options.

#     Returns:
#       Folder type: The folder object for the mount.

#     Raises:
#       ExpError: on failure
#       ExpError: When invalid 'protocol_type' is passed.
#     """

#     # Lazy importing Folder due to cyclic import.
#     from framework.operating_systems.folder.folder import Folder

#     if kwargs.get("dns_ip", None):
#       self.set_dns(kwargs["dns_ip"], append=kwargs.pop('append', True))

#     if kwargs.get("protocol_type", None):
#       protocol_type = kwargs["protocol_type"]
#     else:
#       protocol_type = "SMB"

#     if remount:
#       self.unmount(path, lazy_unmount=True, ignore_errors=True)

#     cmd_list = []
#     if protocol_type == "NFS":
#       cmd_list.append("sudo mount ")
#       cmd_list.append("-t nfs ")
#       if kwargs.get("verbose", True):
#         cmd_list.append("-v ")
#       mount_options = "vers=%s" % kwargs.get("nfs_version", 4)
#       if kwargs.get("linux_mount_options", None):
#         mount_options += ",%s" % kwargs["linux_mount_options"]
#       cmd_list.append("'%s' '%s' " % (network_path, path))
#       #linux_mount_options = "proto=tcp,port=2049"
#       cmd_list.append("-o %s " % mount_options)

#     elif protocol_type == "SMB":
#       cmd_list.append("sudo mount -v")
#       cmd_list.append("-t cifs")
#       cmd_list.append("'%s' '%s'" % (network_path, path))
#       opt_str = ""
#       mount_options = kwargs.get("linux_mount_options", None)
#       if mount_options:
#         opt_str = ",".join(mount_options)

#       cmd_list.append("-o username=%s,password=%s,domain=%s,noac,%s" % \
#           (username, password, domain_name, opt_str))

#     else:
#       raise ExpError("Invalid protocol_type used: '%s'."
#                              % protocol_type)

#     self.execute("sudo mkdir -p %s" % (path), ignore_errors=True)

#     cmd = " ".join(cmd_list)
#     DEBUG("Mounting on linux with the command: %s" % cmd)
#     self.execute(cmd, timeout=kwargs.get("timeout", 60))

#     return Folder(host=self, path=path, on_mount=True)

  def ping_an_ip(self, ip, count=3, packet_size=None, wait_time=None):
    """
    This method is used to ping any ip from UVM.

    Args:
      ip(str) : ip that needs to be pinged.
      count(int) : The number of times IP should be pinged. Default is 3 times.
      packet_size (int, Optional): The packet size in Bytes to ping.
      wait_time (int, Optional): Time in milliseconds to wait for a reply for
        each packet sent.

    Returns:
      status(int) : 0 on success and 1 on failure.

    """
    cmd = "ping -c %s %s" %(count, ip)
    if packet_size is not None:
      cmd += " -s %s" % packet_size
    if wait_time is not None:
      cmd += " -W %s" % wait_time
    INFO(cmd)
    result = self.execute(cmd, ignore_errors=True)
    if "timed out" in result["stdout"] or "Destination Host Unreachable" in\
      result["stdout"] or "unknown host" in result["stdout"]:
      result["status"] = 1
    return result["status"]

  def poweroff(self, run_as_root=True):
    """This method is used to shutdown a machine.

    Args:
      run_as_root(bool, optional): True when poweroff is to be done with super
      user permissions, False otherwise.

    """
    try:
      self.execute("poweroff", run_as_root=run_as_root)
    except ExpError:
      pass

  def reboot(self, timeout=60):
    """This method is used to reboot a machine.

    Args:
      timeout (int, optional): Timeout for the operation in seconds.

    Returns:
      None

    Raises:
      None
    """
    try:
      self.execute("sudo reboot", timeout=timeout)
    except ExpError:
      pass

  @retry(retries=3, exception_list=[ExpError])
  def rm(self, file_path, force=True, recurse=False, run_as_root=False,
         ignore_errors=False, disable_safe_rm=True):
    """This method is used to remove files directory.

    Args:
      file_path (str): Path of the directory or file.
      force (bool, optional): Force file delete.
        Default: True.
      recurse (bool, optional): Recursively delete files.
        Default: False.
      run_as_root (bool, optional): Boolean to decide, Should the command be
        run as root or not.
        Default: False.
      ignore_errors (bool or callable, optional): To decide whether or not to
        ignore errors.
      disable_safe_rm (bool, Optional): Whether to disable safe rm or not.
                                        Defaults to True.

    Returns:
      dict: With keys "status" and "output" of the command execution.

    Raises:
      None
    """
    cmd_list = []
    if run_as_root:
      cmd_list.append("sudo")
    cmd_list.append("rm")
    if force:
      cmd_list.append("-f")
    if recurse:
      cmd_list.append("-r")
    cmd_list.append(file_path)
    self.execute(cmd=" ".join(cmd_list), ignore_errors=ignore_errors,
                 disable_safe_rm=disable_safe_rm)

  def set_dns(self, dns_ip, append=True):
    """Set DNS server for the Linux UVM.

    Args:
      dns_ip(str): Ip address of the Domain Name Server.
      append(bool): Set as true to append the DNS. Defaults to True.

    Raises:
      ExpError: on failure
    """
    mode = ">>" if append else ">"
    cmd = "sudo sh -c \"echo nameserver %s %s /etc/resolv.conf\""\
           % (dns_ip, mode)
    DEBUG("Adding %s to the list of nameservers." % dns_ip)
    self.execute(cmd)

  def scp(self, src_path, dest_path):
    """This method is used to copy files/folders from one location to another.

    Args:
      src_path (str): Source path.
      dest_path (str): Destination path

    Returns:
      None

    Raises:
      None

    """
    key_path = ManageKeys.get_ssh_keys()

    self.execute("scp -i %s -o StrictHostKeyChecking=no -o "
                 "UserKnownHostsFile=/dev/null -r %s %s" % (key_path,
                                                            src_path,
                                                            dest_path))

  def start_io(self, **kwargs):
    """Method to start IO with specific load.

    Kwargs:
      tool(IOTools, optional): The tool to use for io.
      Default: IOTools.DD

    Raises:
      ExpError: If tool is not from IOTools
    """
    tool = kwargs.pop('tool', IOTools.DD)
    if tool == IOTools.DD:
      self.__start_dd_io(**kwargs)
    elif tool == IOTools.FIO:
      self.__start_fio_io(**kwargs)
    elif tool == IOTools.DISK_PERF:
      self.__start_disk_perf_io(**kwargs)
    else:
      raise ExpError("Invalid IO tool used: '%s'." % tool)

  def tar(self, files_list, tar_path="/tmp/files.tar.gz", timeout=300,
          run_as_root=False, exclude_patterns=""):
    """Make a tar.gz format tar file with all the files included.

    Args:
      files_list(list): List of file/folder paths to be packed together.
      tar_path(str, optional): Path of the tar.gz file to be made. If not
        specified, tar file will be created in /tmp dir with a random name.
        Default: /tmp/files.tar.gz
      timeout (int): Command execution timeout. Defaults to 300sec.
      run_as_root (bool, optional): Boolean to decide, should tar operation be
        run as root or not.
        Default: False.
      exclude_patterns (str, optional): Patterns to omit from the tar command.

    Returns: None

    Raises:
      ExpError: when the tar command failed to execute.
    """
    # Check if the tar already exists, If so remove it.
    if self.exists(tar_path):
      self.rm(tar_path, force=True, run_as_root=run_as_root)

    # Check if the tar folder exists, else create one.
    tar_folder = '/'.join(tar_path.split('/')[0:-1])
    if not self.exists(tar_folder):
      self.mkdir(tar_folder)

    # Check that bzip2 is installed, needed for -j option in tar.
    result = self.execute("which bzip2", ignore_errors=True)
    if result['status']:
      DEBUG("Bzip2 not installed which is needed for tar, installing")
      self.install("bzip2")

    if not exclude_patterns:
      cmd = "tar -cjf %s -C %s ." % (tar_path, " ".join(files_list))
    else:
      cmd = "tar --exclude=%s -cjf %s -C %s ." % (exclude_patterns,
                                                  tar_path,
                                                  " ".join(files_list))
    result = self.execute(cmd, timeout=timeout, run_as_root=run_as_root)
    if result["status"]:
      raise ExpError("Failed to execute command: %s" % cmd)

  def touch(self, _file):
    """This method is used to touch a file.

    Args:
      _file (str): Path of the file.

    Returns:
      None
    """
    self.execute("touch %s" % _file)

  def transfer_from(self, remote_path, local_path=None, retries=3, timeout=360,
                    wildcard=False, validate_checksum=False):
    """Transfers a file from remote server

    Args:
      remote_path(str): Remote path of the file to be transferred.
      local_path(str): Local path of the file to be copied.Default=None.
      retries(int, optional): Maximum number  of attempts to transfer the file.
        Default: 3
      timeout(int, optional): Maximum waiting time for transfer in seconds.
        Default: 360 seconds.
      wildcard(bool, optional): Pass True if remote_path is file/directory name
                                with wildcard entries. Note that local_path must
                                be a directory if True is passed.
        Default: False.
      validate_checksum(bool, optional): Validate checksums of file taken at
                                         source path before downloading and
                                         at destination path after
                                         downloading. Try downloading the file
                                         with 3 retries in case checksums
                                         don't match. Currently, this option
                                         can be used ONLY when wildcard is set
                                         to False.
        Default: False.

    Returns:
      (dict): With keys "status" and "output" of the command execution.

    Raises:
      ExpError: When wildcard=True and local_path is not directory.
        When no matching files/directories are found.
      ExpError: In case checksums don't match even after 3 retries.
    """
    if local_path is None:
      local_path = os.environ.get("NUTEST_LOGDIR", "/tmp/")

    if self._local_vm:
      return self.cp(remote_path, local_path)

    if wildcard:
      if not os.path.isdir(local_path):
        raise ExpError("The local_path %s must be a directory since "
                               "wildcard is True" % local_path)
      python_version = get_highest_python_version(self)
      command = python_version + " -c 'import glob; print(glob.glob(\"" +\
                remote_path + "\"))'"
      result = self.execute(command)
      if "[]" in result.get('stdout'):
        raise ExpError("Copy Error. No files/directories matching the "
                               "pattern %s" % remote_path)
      result = result.get('stdout').strip()
      files = result[1:len(result)-1].split(', ')
      _files = [file[1:len(file)-1] for file in files]
      for _remote_path in _files:
        self._ssh.transfer_from(_remote_path, local_path,
                                retries=retries, timeout=timeout)
    else:
      if not validate_checksum:
        self._ssh.transfer_from(remote_path, local_path,
                                retries=retries, timeout=timeout)
      else:
        filename = os.path.basename(remote_path)
        dst_filepath = os.path.join(local_path, filename)
        num_retries = 3
        attempt = 0
        while attempt < num_retries:
          DEBUG("Attempt {}/{} to download the tar file".format(
            attempt + 1, num_retries))
          src_checksum = self.get_checksum(path_list=[remote_path])[0]
          self._ssh.transfer_from(remote_path, local_path,
                                  retries=retries, timeout=timeout)
          dst_checksum = LinuxOperatingSystem().get_checksum(
            path_list=[dst_filepath])[0]
          DEBUG("Checksum of {} (source: {}): {}\nChecksum of {} "
                "(destination: {}): {}".format(
                  remote_path, self.ip, src_checksum,
                  dst_filepath, LinuxOperatingSystem().ip, dst_checksum))
          if str(src_checksum) == str(dst_checksum):
            break
          attempt += 1
        else:
          raise ExpError("Exhausted {} attempts to download the tar file "
                            "{} to tester by comparing the checksum".format(
                              num_retries, remote_path))

  def transfer_to(self, local_path, remote_path, retries=3, timeout=360,
                  wildcard=False, perm=None, close_ssh_connection=False):
    """Transfers a local file to remote server

    Args:
      local_path(str): Local path of the file to be transferred.
      remote_path(str): Remote path of the file.
      retries(int, optional): no of retries.
        Default: 3
      timeout(int): timeout for transfer.
        Default: 360
      wildcard(bool, optional): Pass True if local_path is file/directory name
                                with wildcard entries. Note that remote_path
                                must be a directory if True is passed.
        Default: False
      perm(str): Permission to be set on remote file.
      close_ssh_connection (bool, Optional): Flag to set whether to close the
                                      SSH connection used for command execution.
                                      False by default.

    Returns:
      (dict): With keys "status" and "output" of the command execution.

    Raises:
      ExpError: When wildcard=True and remote_path is not directory.
        When no matching files/directories are found.
    """
    if self._local_vm:
      return self.cp(local_path, remote_path)

    if wildcard:
      command = "python -c 'import os;print True if os.path.isdir(\"" \
                + remote_path + "\") else False\'"
      result = self.execute(command, close_ssh_connection=close_ssh_connection)
      if result.get('stdout').rstrip() == 'False':
        raise ExpError("The remote_path %s must be a directory since "
                               "wildcard is True" % remote_path)
      local_files = glob.glob(local_path)
      if not local_files:
        raise ExpError("Copy Error. No files/directories matching the "
                               "pattern %s" % local_path)
      for _local_path in local_files:
        self._ssh.transfer_to(_local_path, remote_path, retries,
                              timeout, perm=perm,
                              close_ssh_connection=close_ssh_connection)
    else:
      return self._ssh.transfer_to(local_path, remote_path, retries=retries,
                                   timeout=timeout, perm=perm,
                                   close_ssh_connection=close_ssh_connection)

  def transfer_fileobj_to(self, fileobj, remote_path, **kwargs):
    """Transfers a file-like object to remote host.

    Args:
      fileobj (file-like): An open file-like object.
      remote_path (str): Remote path on the host to transfer the file to.
    """
    try:
      self._ssh.transfer_fileobj_to(fileobj, remote_path, **kwargs)
    except ExpError as exc:
      if "No such file or directory" in str(exc):
        remote_directory = remote_path[:remote_path.rindex("/")]
        DEBUG("Creating directory %s on host %s" % (remote_directory, self.ip))
        self.mkdir(remote_directory)
        self._ssh.transfer_fileobj_to(fileobj, remote_path, **kwargs)
      else:
        raise

  def cp(self, src, dst, recursive=True, **kwargs):
    """Perform linux cp of src to dst.

    Args:
      src (str): Source file/dir.
      dst (str): Destination file/dir.
      recursive (bool): If cp should be done with -R flag. Default: True.

    Returns:
      (dict): With keys 'status', 'stdout', 'stderr' of the command execution.

    Raises:
      ExpError: If cp fails in local_vm mode.
    """
    cmd = "cp "
    if recursive:
      cmd += "-R "
    cmd += "%s %s" % (src, dst)

    if self._local_vm:
      result = self.local_execute(cmd)
      if result['status'] != 0:
        raise ExpError(
          "Unable to perform cmd %s: %s" % (cmd, result))
      return result
    else:
      return self.execute(cmd, **kwargs)

  @retry(retries=3, exception_list=[ExpError])
  def unmount(self, path, force=False, ignore_errors=False, lazy_unmount=False):
    """Method to unmount the specified path.

    Args:
      path(str): Local path to unmount.
      force (bool, optional): Unmount forcefully if True.
      ignore_errors (bool or callable, optional): Whether or not to ignore
        errors.
        Default: False.
      lazy_unmount (bool, optional): Set it to true to do a lazy unmount

    Returns:
      None

    Raises:
      None
    """
    option = ""
    if force:
      option += "-f"
    if lazy_unmount:
      option += " -l"
    cmd = "sudo umount %s %s" % (option, path)
    self.execute(cmd=cmd, ignore_errors=ignore_errors)

  def untar_file(self, tar_filepath, untar_path="", timeout=1800):
    """untar a tar file

    Args:
      tar_filepath(str): path of the file for untar.
      untar_path(boolean, optional): Path of directory, where the file needs
        to be untared.
        Default: ""
      timeout(int): Wait time in seconds for untar to complete.
        Default: 1800

    Returns: Dictionary of status, output and stderr.

    TODO:- Code needs a lot improvement.
    """
    basename = os.path.basename(tar_filepath).replace(".tar.gz", "")

    cmd1 = f"tar --use-compress-program=pigz -xvf {tar_filepath}"
    cmd2 = f"tar --use-compress-program=gzip -xvf {tar_filepath}"
    cmd3 = f"tar -xvf {tar_filepath}"

    if untar_path:
      mkdir_cmd = "mkdir -p %s" % untar_path
      self.execute(cmd=mkdir_cmd, ignore_errors=True)

      try:
        # Check untar using pigz
        cmd = ("if [ -d %s/%s ]; then echo 'already untarred'; " \
               "else %s -C %s; fi;" % (untar_path, basename, cmd1,
                                       untar_path))
        response = self.execute(cmd=cmd, retries=3, timeout=timeout)
      except ExpError:
        WARN(f"pigz is not supported program for decompression")
        try:
          # Check untar using gzip
          cmd = ("if [ -d %s/%s ]; then echo 'already untarred'; " \
                 "else %s -C %s; fi;" % (untar_path, basename, cmd2,
                                         untar_path))
          response = self.execute(cmd=cmd, retries=3, timeout=timeout)
        except ExpError:
          WARN(f"gzip is not supported program for decompression")
          # Check untar without any compression program
          cmd = ("if [ -d %s/%s ]; then echo 'already untarred'; " \
                 "else %s -C %s; fi;" % (untar_path, basename, cmd3,
                                         untar_path))
          response = self.execute(cmd=cmd, retries=3, timeout=timeout)

    else:
      try:
        # Check untar using pigz
        response = self.execute(cmd=cmd1, retries=3, timeout=timeout)
      except ExpError:
        WARN(f"pigz is not supported program for decompression")
        try:
          # Check untar using gzip
          response = self.execute(cmd=cmd2, retries=3, timeout=timeout)
        except ExpError:
          WARN(f"gzip is not supported program for decompression")
          # Check untar without any compression program
          response = self.execute(cmd=cmd3, retries=3, timeout=timeout)

    return response

  def start_stress_cpu(self, timeout=60, background=True, **kwargs):
    """This method starts the stress tool found on linux uvms.
       (Centos6.6 UVM 1.3 has "stress" installed as a tool)

    Args:
       timeout(int, optional) : Maximum wait time for the completion of the
        command execution. Please note that, if the background is False,
        the timeout value should be greater than 'stress_cmd_timeout' in kwargs.
        Default : 60
       background (bool, optional): Whether the workload must be run in the
        background or not. Default: True
       kwargs(dict, optional) : Contains key-value pairs of parameters to be
                                sent.
          cpu(int): Number of process to stress CPU.
          io(int) : Number of IO stress testing process.
          hdd(int): Number of hard disk exercising process.
          vm(int) : Number of Vm stress testing process.

    Raises:
      ExpError: Raise an exception if arguments are not passed to stress
      command.
    """
    # if arguments are not passed to stress command, it will throw ExpError.
    if not kwargs:
      raise ExpError("Options are mandatory to stress command")

    cmd = "stress "
    stress_cmd_timeout = kwargs.pop("stress_cmd_timeout", "1200s")
    cmd += " ".join(["--%s %s" % (opt, val) for opt, val in kwargs.items()
                     if val])
    cmd += " --timeout %s > /dev/null 2>&1" % stress_cmd_timeout
    self.execute(cmd, background=background, timeout=timeout)
    DEBUG("Command %s executed successfully" % cmd)

  def zero_out_disk(self, disk_path, disk_size=None, bs=1048576):
    """This method is used to zero out raw disk attached to a UVM.

    Args:
      disk_path(str): Path of disk to be zeroed.
      disk_size (int): The size of the disk.
      bs(int): "Sizes in byte" unit. If bs = 1048576, then 1 unit = 1048576 byte
        i.e. The disk size will be in the unit MB.
        Default: 1048576.

    Raises:
      ValueError: When the file of the disk cannot be fetched and calculated.
    """
    if not disk_size:
      disk_size_line = "sudo fdisk -l | grep 'Disk %s:'" % disk_path
      result = self.execute(disk_size_line)
      disk_size_match = re.search(r", (\d+) bytes", result["stdout"])
      if not disk_size_match:
        raise ValueError("Failed to get disk size for %s" % disk_path)
      disk_size = disk_size_match.group(1)
    count = int(disk_size) / bs
    cmd = "sudo dd if=/dev/zero of=%s bs=%s count=%s seek=0" % (disk_path, bs,
                                                                count)
    self.execute(cmd=cmd, timeout=10*60)

  def lsscsi(self):
    """
    This function uses lsscsi to list all the SCSI devices attached to this VM.

    Returns:
      [{
      'scsi_host'         : int,
      'channel'           : int,
      'target_number'     : int,
      'LUN'               : int,
      'peripheral_type'   : str,
      'device_node_name'  : str
      }]
      A list of dictionaries represented in the above format.

    """
    ret = []
    result = self.execute('lsscsi')['stdout']
    lines = result.splitlines()
    for line in lines:
      words = line.split()
      device = words[-1]
      host, channel, target, lun = words[0][1:-1].split(':')
      peripheral_type = (words[0].split(']')[1] if
                         words[1] == 'NUTANIX' else words[1])
      if re.match(r'^-$', device):
        # Not a SCSI device. Could be a remote attached NVMe device.
        # While lsscsi is capable of parsing locally attached NVMe device,
        # it may not work for NVMe over TCP or RDMA. The recommendation is to
        # use lsscsi for SCSI devices and nvme list for NVMe devices.

        # Sample output of lsscsi when remote nvme device is attached.
        # [0:0:1:0]    disk    NUTANIX  VDISK            0     /dev/sdb
        # [3:0:0:0]    disk    NUTANIX  VDISK            0     /dev/sdc
        # [N:1:12:1]   disk    SPDK bdev Controller__1                    -
        continue
      ret.append({
        'scsi_host'         : host,
        'channel'           : channel,
        'target_number'     : target,
        'LUN'               : lun,
        'peripheral_type'   : peripheral_type,
        'device_node_name'  : device
      })

    return ret

  def transfer_cmd_output_file(self, cmd, out_file, local_path, **kwargs):
    """Executes the given command, redirects the output to a file and
    then transfers the file to the path specified in tester.

    Args:
      cmd (str): Command to execute.
      out_file (str): File where the output of the command is redirected
      local_path (str): Local path of the file to be copied.
      **kwargs : Takes optional parameters of execute() method
    """
    cmd += " > %s" % out_file
    self.execute(cmd, **kwargs)
    self.transfer_from(remote_path=out_file, local_path=local_path)

  def get_active_interfaces(self):
    """Returns the names of the interfaces that are up.

    Args:
      None.

    Returns:
      List: A list of interface names that are up.
    """
    stdout = self.execute("/sbin/ifconfig | grep eth[0-9]")["stdout"]
    lines = stdout.split("\n")
    interfaces = [re.compile("^(eth.+?)(?=:?\\s)").findall(line) for line
                  in lines]
    return sum(interfaces, [])

  def lsblk(self, **kwargs):
    """
    This method is used to lists information about all
    available or the specified block devices.

    Kwargs:
      devices(list, optional) : List of specified block devices.

    Returns:
      [{
        'MAJ:MIN': '8:0',
        'NAME': 'sda',
        'MOUNTPOINT': '',
        'RM': '0',
        'RO': '0',
        'TYPE': 'disk',
        'SIZE': '15M'
      }]
      list: A list of dictionaries represented in the above format.
    """
    cmd = "lsblk -P "
    if kwargs.get("devices"):
      cmd += " ".join(kwargs["devices"])

    result = self.execute(cmd=cmd)["stdout"].splitlines()
    result = [dict(map(str.strip, info.split('=', 1)) for info in block.split()
                   if '=' in info) for block in result]

    return [{key: val.replace('"', '') for key, val in block.items()}
            for block in result]

  def df(self, **kwargs):
    """
    This method display information related to file
    systems about total space and available block space

    Kwargs:
      devices(list, optional) : List of specified block devices.
      option(str, optional) : option or flag to be used for df

    Returns:
      [{
        'Use%': '0%',
        'Used': '0',
        'Avail': '13G',
        'Filesystem': 'devtmpfs',
        'Type': 'devtmpfs',
        'Mounted on': '/dev',
        'Size': '13G'
      }]
      list: A list of dictionaries represented in the above format.
    """
    cmd = "df -T -{} ".format(kwargs["option"]) if kwargs.get("option")\
          else "df -T "
    if kwargs.get("devices"):
      cmd += " ".join(kwargs["devices"])

    result = [block.split() for block in self.execute(cmd=cmd)["stdout"].
              splitlines()]
    result[0][-2:] = [' '.join(result[0][-2:])]

    return [dict(zip(result[0], value)) for value in result[1:]]

  def cat(self, file_path, run_as_root=False):
    """
    This method display contents of file.

    Args:
      file_path(string) : File Path
      run_as_root(bool) : True if run as root privilege else False.

    Returns:
      str: file contents
    """
    cmd = "sudo cat" if run_as_root else "cat"
    cmd += " {}".format(file_path)
    return self.execute(cmd=cmd)["stdout"]

  def validate_and_copy_yum_repos(self, repos=None):
    """
    Helper method to validate and copy yum repos.
    Args:
      repos(List): if only specific repos to be installed.
                    by default, all the repos would be copied.
    Returns:
      None

    Raises:
      ExpError: when yum repos url are not present
      for the respective os version.

    """
    # This should handle 99% of the things we install. The only reason we
    # would fallback is if the defined repos don't contain the given package.
    # This is cleaner than constantly falling back and installing from some
    # user defined packages on endor which is prone to breakage.
    os_ver = self.get_os_version()
    repos_installed = self.all_repos_installed(os_ver, repos)
    if repos_installed is None:
      raise ExpError( \
        "No repos to use for install for {} on {}".format(os_ver, self.ip))
    elif not repos_installed:
      DEBUG("Missing/different repos on {}, copying repos".format(self.ip))
      self.copy_yum_repos(os_ver, repos)

  def copy_yum_repos(self, os_ver=None, repo_names=None):
    """
    Helper method to download urls to the OS.
    Args:
      os_ver (dict): get_os_version output.
      repo_names (List): only repos specified will be copied.
    Returns:
      None.
    """
    urls = self._get_yum_urls(os_ver)
    if not urls:
      return None
    tmp_path_on_svm = "/tmp/nutest_yum_repos"
    self.mkdir(tmp_path_on_svm)
    is_any_downloaded = False
    for url in urls:
      is_download_repo = False
      if repo_names:
        if os.path.basename(url) in repo_names:
          is_download_repo = True
      else:
        is_download_repo = True
      if is_download_repo:
        is_any_downloaded = True
        self.download_file(url,
                           os.path.join(tmp_path_on_svm, os.path.basename(url)))
    if is_any_downloaded:
      self.execute("sudo mv %s/* %s" % (tmp_path_on_svm,
                                        self.SVM_YUM_REPO_PATH))
    self.rm(tmp_path_on_svm, recurse=True)

  def all_repos_installed(self, os_ver=None, repos=None):
    """
    Check if all the defined repos are installed on the OS.
    Args:
      os_ver (dict): get_os_version output. Defaults to None.
      repos (List): set of repo names to be validated. Defaults to None.
    Returns:
      bool/None: True/False if they all are installed or not, None if no
                 urls are found in YUM_REPO_URLS.
    """
    local_repos = repos
    if not local_repos:
      urls = self._get_yum_urls(os_ver)
      if not urls:
        return None
      local_repos = [os.path.basename(url) for url in urls]
    # Get the yum repo file names. We're assuming the filename on the SVM
    # will match what's on the webserver. If they don't, we assume something
    # has changed and we'll download again.
    cmd = "ls -l {} | awk '{{print $9}}'".format(self.SVM_YUM_REPO_PATH)
    result = self.execute(cmd)
    vm_repos = \
      [os.path.basename(repo).strip() \
       for repo in result["stdout"].splitlines() if repo]
    DEBUG("Local yum repos: {}".format(local_repos))
    DEBUG("VM yum repos: {}".format(vm_repos))
    return set(vm_repos) == set(local_repos)

  def _get_yum_urls(self, os_ver=None):
    """
    Get the yum urls for the given os_ver. If os_ver isn't defined it is
    fetched.
    Args:
      os_ver (dict): get_os_version output. Defaults to None.
    Returns:
      list: List of yum urls.
    """
    if not os_ver:
      os_ver = self.get_os_version()
    urls = YUM_REPO_URLS.get(os_ver['distro'], {}).get(os_ver['major'], [])
    if not urls:
      ERROR("No defined yum repos found for {} on {}".format(os_ver, self.ip))
    return urls

  def _download_file(self, url, local_path, timeout=600, retries=3,
                     retry_interval=60, **kw_options):
    """Method to download a file from remote HTTP location.
    Args:
      url(str): URL location for download the file from.
      local_path(str): Absolute local path to save file to.
      timeout(int,optional): Wait time in seconds, after which the operation
        will be aborted.
        Default: 600 seconds.
      retries(int, optional): Number of retries for the wget command to succeed.
        Default: 3.
      retry_interval(int, optional): Sleep interval between retries. Default:
        60 seconds.
      kw_options (dict, optional): Keyword options fo wget.

    Returns:
      bool: True on successful download. Raises exception otherwise.

    Raises:
      ExpError.

    Notes:
      This routine doesn't return False on Failure download. Instead,
        it will raise the exception.
    """
    cmd = "wget --progress=dot:giga --tries=1 %s -O %s" % (url, local_path)

    # Options without values won't be handled by the following block.
    for key, value in kw_options.items():
      if key in ('progress', 'tries'):
        continue
      cmd += " --%s %s" % (key.replace("_", "-"), value)

    attempts = 0
    while attempts < retries:
      attempts += 1
      response = self.execute(cmd, timeout=timeout, ignore_errors=True)

      if response['status']:
        # retry will be attempted in case of below issues,
        # 1. when wget fails due to network issue (status of 4).
        # 2. when wget fails due to intermittent filer issue(status of 8)
        # 3. when response has "Text file busy".
        if response['status'] in (4, 8) or \
          "Text file busy" in response['stdout']:
          WARN("wget failed with response %s. Retrying..." % response)
          time.sleep(retry_interval)
        else:
          # All other issues should raise exception.
          raise ExpError("Failed to run wget.")
      else:
        # No need to retry since wget succeeded (return status == 0).
        return True
    return False

  @staticmethod
  def __handle_safe_rm(cmd):
    """Helper to inspect command and handle safe rm

    Process the command and prepend "export USE_SAFE_RM=no" to the command if
    cmd has "rm ".

    Args:
      cmd (str): Command string.

    Returns:
      str: Modified cmd string if rm is present else the original cmd itself.
    """
    if "rm " in cmd:
      cmd = "export USE_SAFE_RM=no ; " + cmd
    return cmd

  def __execute(self, cmd, retries=3, timeout=60, tty=True, run_as_root=False,
                background=False, log_response=True, conn_acquire_timeout=360,
                close_ssh_connection=False, disable_safe_rm=True,
                log_command=True, async_=False, session_timeout=10):
    """Method which execute a remote or local Command.

    Args:
      cmd(str): Command to execute
      retries(int, optional): Maximum attempt to successfully execute the
        command.
        Default: 3
      timeout(int, optional): Maximum wait time for the completion of the
        command execution.
        Default: 60
      tty (bool, optional): If a TTY should be used on not. Defaults to True.
      run_as_root (bool, optional): If True, run the command as root (use sudo).
      background(bool, Optional): same as 'background' option of execute()
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False.
      conn_acquire_timeout (timeout, Optional): Maximum time to acquire/create
                            a connection.
                            Defaults to 360 seconds.
      close_ssh_connection (bool, Optional): Flag to set whether to close the
                                    SSH connection used for command execution.
                                    False by default.
      disable_safe_rm (bool, Optional): Whether to disable safe rm or not.
                                        Defaults to True.
      log_command (bool, Optional): Whether to log the command passed. Would
                                    be used while running commands including
                                    passwords. Defaults to True.
      async_ (bool, Optional): Flag to specify
      if ssh command execution should be asynchronous.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.

    Returns:
      dict: With keys "status", "stdout"  and "stderr" of the command execution

    """
    if run_as_root:
      cmd = "sudo %s" % cmd
    if self._local_vm:
      DEBUG("localhost>> %s" % cmd)
      return self.local_execute(cmd)
    else:
      if disable_safe_rm:
        cmd = self.__handle_safe_rm(cmd)
      DEBUG("%s>> %s" % (self.ip, cmd))
      return self._ssh.execute(cmd, retries=retries, timeout=timeout, tty=tty,
                               background=background,
                               log_response=log_response,
                               conn_acquire_timeout=conn_acquire_timeout,
                               close_ssh_connection=close_ssh_connection,
                               log_command=log_command,
                               async_=async_,
                               session_timeout=session_timeout)

  def __start_dd_io(self, **kwargs):
    """Start IO using 'dd' tool.
    Returns: Dictionary of status, output and stderr.
    """
    # Extract values from kwargs
    tmp_path = FilePath(FilePath.LINUX, "/", "tmp", "nutest_dd_file")
    blocksize = kwargs.get('bs', 1048576)
    count = kwargs.get('num_blocks', 1024)
    input_file = kwargs.get('pattern', 'random')
    output_file = kwargs.get('out_file', tmp_path.get())
    timeout = kwargs.get('timeout', 300)
    background = kwargs.get('background', False)
    if input_file == 'random':
      pattern = '/dev/urandom'
    else:
      pattern = '/dev/zero'
    # Compose the DD command with fsync to flush all the data to disk
    # immediately.
    cmd = "sudo /bin/dd if=%s of=%s count=%s bs=%s conv=fsync" % (pattern,
                                                                  output_file,
                                                                  count,
                                                                  blocksize)
    return self.execute(cmd=cmd, timeout=timeout, background=background)

  def __start_disk_perf_io(self, **kwargs):
    """This routine is used to start disk_perf IO.

    Args:
      **kwargs: Takes following parameters:
        out_file (str): File location to be written.
        blocksize (int, optional): Block size of the IO to be written. Default:
          1048576.
        count (int, optional): Number of blocks to be written. Default: 1024.
        timeout (int): Timeout in seconds for the workload. Default: 300.
        pattern (str, optional): The string defines the pattern of IO to be
          written to be either 'random' or 'sequential'. Default: 'random'.

    Returns:
      (dict): 'status' and 'output' of the disk_perf output.
    """
    cmd = DiskPerfCommandGenerator(**kwargs)
    tmp_path = FilePath(FilePath.LINUX, "/", "tmp", "nutest_dd_file")
    cmd.target = kwargs.get("out_file", tmp_path.get())
    cmd.block_size = kwargs.get('blocksize', 1048576)
    cmd.count = kwargs.get('count', 1024)
    timeout = kwargs.get('timeout', 300)
    random = kwargs.get('pattern', 'random')
    if random == 'random':
      cmd.random = True
      cmd.random_seed = 1
    else:
      cmd.random = False
      cmd.random_seed = -1
    cmd.repeat_write_skip_size = kwargs.get('repeat_write_skip_size', 1048576)

    return self.execute(cmd=cmd.generate_command(), timeout=timeout)

  def __start_fio_io(self, timeout=300, run_as_root=True,
                     background=False, **kwargs):
    """Starts fio workload.

    Args:
      timeout (int): Timeout in seconds for the workload. Note that this is
        trivial if the workload is to be run in the background.
        Default: 300
      run_as_root (bool): Whether the command must be executed with superuser
        privileges.
        Default: True
      background (bool): Whether the workload must be run in the background or
        not.
        Default: False
      kwargs:
        name (str): Name of the fio job.
        filename (str): Path of the job's target.
        readwrite / rw (str): IO pattern of the job.
        ... (str): These depend on the options and job parameters supported by
          fio. If no value is associated with the option/parameter, it must be
          passed with value None.

    Returns:
      (dict): The status, stdout and stderr resulting from the execution of the
        fio command.

    Sample Usage:
      <LinuxOperatingSystem Object>.start_io(tool=IOTools.FIO, timeout=60,
                                             name="diskloopwrite",
                                             filename="/dev/sdb",
                                             rw="randwrite",
                                             timebased=None,
                                             runtime="30s")

    Notes:
      fio is capable of running multiple different jobs in a single command
        execution, but this method only supports one job definition per
        execution. "numjobs" may be used to execute clones of the single job.
      fio-2.0.13 seems to be present in the 1.2 version of Centos64UVM
        goldimages in use, so it would be convenient to consider that version by
        default.
    """
    # Build the fio command.
    command = " ".join(["fio",
                        " ".join(["--%s=%s" % (opt, val)
                                  if val is not None else "--%s" % opt
                                  for opt, val in kwargs.items()])])

    # Execute the fio command.
    execute_kwargs = {
      'timeout': timeout,
      'run_as_root': run_as_root,
      'background': background
    }
    if background and run_as_root:
      execute_kwargs['tty'] = True
      execute_kwargs['trailing_sleep'] = True
    return self.execute(command, **execute_kwargs)

  def __use_fallback_install_options(self, package_name, releasever,
                                     architecture):
    """
    This method installs package from releasever repo provided.

    NOTE:
      Centos 7.3.1611 repo has been removed and will no longer gets any updates,
      nor any security fix's. This method is added as a fallback mechanism

    Args:
      package_name(str): package name to install on local machine.
      releasever (int): This specifies the centos repo version to be used.
      architecture (CPUArchitecture): CPU Architecture of hypervisor, used to
        fetch corresponding path for yum RPMs.

    Returns:
      None

    Raises:
      ExpError: when the command failed to execute
    """
    DEBUG("Disabling EPEL repo and trying to install : %s" % package_name)
    cmd = "sudo yum install -y --nogpgcheck --disablerepo=epel %s " \
          % (package_name)
    result = self.execute(cmd=cmd, timeout=600, ignore_errors=True)
    if not result["status"]:
      DEBUG("Successfully installed {} from configured yum repo"
            .format(package_name))
      return

    if package_name in LinuxOperatingSystem.PACKAGES_IN_LOCAL_REPO:
      DEBUG("Trying to install Package: %s from local filer" % package_name)
      if releasever == 8:
        yum_endor_path = "http://endor.dyn.nutanix.com/nutest/yum_el8/"
      else:
        yum_endor_path = "http://endor.dyn.nutanix.com/nutest/yum/"

      rpm_url = ("%s/ppc/%s/" if architecture == CPUArchitecture.PPC else
                 "%s/%s/") % (yum_endor_path, package_name)
      download_dir = os.path.join("/tmp", package_name)

      cmd = "ls %s" % download_dir
      ls_status = self.execute(cmd=cmd, ignore_errors=True)

      # We can't find the download directory, or the RPM isn't currently on
      # the VM so we need to mkdir and download it.
      if ls_status["status"] or ".rpm" not in ls_status["stdout"]:
        try:
          self.execute("mkdir %s; wget %s --no-parent --accept='*.rpm'"
                       " --recursive --no-directories --span-hosts --level=1"
                       " --directory-prefix=%s" % (download_dir, rpm_url,
                                                   download_dir), timeout=120)
        except ExpError:
          self.rm(download_dir, recurse=True)

      cmd = "sudo yum localinstall --nogpgcheck -y %s/*" % download_dir
      result = self.execute(cmd=cmd, timeout=600, ignore_errors=True)
      if not result["status"] and \
         "Skipping {}/*".format(download_dir) not in result["stdout"]:
        return

    # Note, with EL8 the below code absolutely won't work. Let's fail early.
    # We should probably just rm -rf this code in the future.
    if releasever == 8:
      raise ExpError("Unable to install {} on EL8".format(package_name))

    DEBUG("Trying to install Package: %s from release version: %s repo" %
          (package_name, releasever))
    yum_base_config_file = "/etc/yum.repos.d/CentOS-Base.repo"
    base_str = r'#\?baseurl=http:\/\/mirror.centos.org\/centos\/\$releasever'
    replacement_str = r'baseurl=http:\/\/vault.centos.org\/centos\/%s' \
                      % releasever
    self.execute("sudo sed -i.bak 's/%s/%s/g' %s"
                 % (base_str, replacement_str, yum_base_config_file))
    try:
      cmd = "sudo yum install -y --nogpgcheck %s " % (package_name)
      self.execute(cmd=cmd, timeout=600)
    except ExpError:
      raise
    finally:
      self.execute("sudo cp %s.bak %s"
                   % (yum_base_config_file, yum_base_config_file),
                   ignore_errors=True)
