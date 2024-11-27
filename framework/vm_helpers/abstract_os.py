"""Python Abstract OS module.

Copyright (c) 2015 Nutanix Inc. All rights reserved.

Author: digvija.dalapat@nutanix.com
        Pranav.Ojha@nutnai.com
"""

#pylint: disable=no-self-use

import abc

class AbstractOperatingSystem(metaclass=abc.ABCMeta):
  """
  Abstract class for OS class.
  """

  @abc.abstractmethod
  def execute(self, cmd, timeout=60, retries=12, ignore_errors=False,
              poll_interval=5, tty=True, run_as_root=False,
              retry_on_regex=None, background=False,
              log_response=True):
    """Execute the given command and return a tuple of the output.

    Args:
      cmd (str): The command to be executed.
      timeout (int): Timeout for the command execution.
      retries (int): The number of retries in case of failures.
      ignore_errors (bool or callable): Whether or not to ignore command
        execution errors. It does not include connection errors. This can also
        be a callable that takes one argument, and returns a bool. The argument
        corresponds to the command execution result, and the return value would
        be whether or not to ignore the error.
        Default: False
      poll_interval (int): The number of seconds to sleep between retries.
      tty (bool): True if tty should be used.
      run_as_root (bool): If True, run as root.
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
                            NOTE: Each of the OS implementation should handle
                            things needed to run the command in background.
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False.
    """

  @abc.abstractmethod
  def mount(self, remote_ip, remote_path, local_mount_path, **kwargs):
    """Method to mount a path.

    Args:
      remote_ip (str): The IP address of the remote machine.
      remote_path (str): The remote path to be mounted.
      local_mount_path (str): The local path where the mount should be made.
    """

  @abc.abstractmethod
  def unmount(self, path, force=False, ignore_errors=False):
    """Method to unmount a path.

    Args:
      path (str): The path to be unmounted.
      force (bool): Unmount forcefully if True.
      ignore_errors (bool or callable, optional): Whether or not to ignore
        errors.
        Default: False
    """

  @abc.abstractmethod
  def start_io(self, **kwargs):
    """Method to start IO with specific load.
    """

  @abc.abstractmethod
  def get_checksum(self, path_list, cksum_type="md5"):
    """Method to get checksum of file(s).

    Args:
      path_list (list): The list of paths.
      cksum_type (str): The type of checksum.
    """
