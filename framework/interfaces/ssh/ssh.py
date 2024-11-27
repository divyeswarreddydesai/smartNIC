#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
#         pranav.ojha@nutanix.com
"""Python module for initiating and executing commands via SSH connection.
"""
# pylint: disable=protected-access,broad-except,invalid-name
# pylint: disable=too-many-branches,too-many-locals,no-else-return
# pylint: disable=useless-else-on-loop,no-else-break,no-else-raise
# pylint: disable=too-many-statements,wrong-import-order,assignment-from-no-return
# pylint: disable=too-many-nested-blocks,len-as-condition,cell-var-from-loop, too-many-lines
# pylint: disable=unused-argument, c-extension-no-member, no-member, redefined-builtin
# pylint: disable=unused-import, reimported, redefined-outer-name, import-outside-toplevel
# pylint: disable=arguments-differ, redefined-argument-from-local, raising-format-tuple

import copy
import inspect
import json
import errno
import mmap
import queue
import os
import re
import six
import socket
import sys
import threading
import time
import traceback
import distutils.spawn  # pylint: disable=no-name-in-module, import-error
from functools import wraps
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import psutil
import paramiko
from paramiko.ssh_exception import AuthenticationException
from paramiko import ProxyCommand
from paramiko.rsakey import RSAKey
from scp import SCPClient

from framework.entities.manage_ip import ManageIPs
from framework.exceptions.interface_error import (
  NuTestSSHError, NuTestSSHTimeoutError, NuTestSSHChannelError,
  NuTestSSHConnectionError, NuTestSSHConnectionTimeoutError,
  NuTestSSHAuthenticationError)
from framework.exceptions.nutest_error import NuTestError
from framework.interfaces.consts import (KEY_FILE, SVM_USER, SVM_PASSWORD,
                                         ClusterCreds)
from framework.lib.decorators import access_control, handle_exception
from framework.lib.error_categorisation import ErrorCategory
from framework.lib.nulog import DEBUG, WARN, ERROR
from framework.lib.recorders import get_recorder
from framework.lib.utils import ping
from framework.lib.lock import lock_file

SSH_CONNECTION_CACHE = {}

NUTEST_PATH = os.environ.get("NUTEST_PATH")
TSH_TRANSFER_SCRIPT_PATH = "/usr/local/bin/teleportqa/copy_from.sh"

MAX_CHANNEL_CREATION_RETRIES = 100

# lock to serialize initialization of paramiko ProxyCommand class
# in teleport env.
tele_proxy_lock = threading.RLock()

class SharedCounter:
  """This gives shared counter object to be used with multiple
  processes/threads. Doing increment/decrement/access of this
  counter value will be threadsafe.
  """
  SIZE = 5

  def __init__(self, value=0):
    """Initializer
    Args:
      value (int): initial value of counter
    """
    exception = None
    for _ in range(3):
      try:
        self._val = mmap.mmap(-1, length=10, access=mmap.ACCESS_WRITE)
        self._write(str(value))
      except KeyError as exc:
        exception = exc
        WARN("Mapping anonymous memory or writing to memory mapped area "
             "failed: %s" % traceback.format_exc())
        time.sleep(5)
      else:
        break
    else:
      memory_info = psutil.Process().memory_info()
      DEBUG("Process Resident Set Size: %s MiB" % (memory_info[0] / 2 ** 20))
      DEBUG("Process Virtual Memory Size: %s MiB" % (memory_info[1] / 2 ** 20))
      raise exception  # pylint: disable = raising-bad-type

    # The lock file should be unique per instance of the shared counter.
    self._lock_file = "ssh_shared_counter_lock_{}".format(id(self))

  def increment(self):
    """Increments counter by 1
    """
    with lock_file(self._lock_file, poll_interval=1):
      value = self._read()
      value += 1
      self._write(value)

  def decrement(self):
    """Decrements counter by 1
    """
    with lock_file(self._lock_file, poll_interval=1):
      value = self._read()
      value -= 1
      self._write(value)

  def value(self):
    """Returns Counter value
    Returns:
      (int): current counter value
    """
    with lock_file(self._lock_file, poll_interval=1):
      return self._read()

  def _read(self):
    """
    Read the value which is stored in the initial bytes by seeking to
    beginning of memory mapped area
    Returns:
      (int): current counter value
    """
    self._val.seek(0)
    value = self._val.readline().decode()
    value = int(value.rstrip('\x00'))
    self._val.seek(0)
    return value

  def _write(self, value):
    """
    Write counter value to anonymous memory map
    Args:
      value (int): value of counter
    """
    value = str(value)
    self._val.write(value.zfill(SharedCounter.SIZE).encode())


method_timeouts = {}


def get_method_timeout(method_name, **kwargs):
  """Get timeout for the input method.
     Calculates the timeout based on max timeout
     for the method + small buffer wait time.

  Args:
    method_name (str): Method Name.
    kwargs     (dict): Keyword dictionary.

  Returns:
    timeout (int): Method timeout.
  """
  # async_buffer is small wait over the total expected
  # execution time of a method.
  async_buffer = 60
  if method_name == "execute":
    if os.environ.get('NESTED_AHV') == "1":
      # Extra wait was added to handle AUTO-21352.
      return kwargs["timeout"] * 3 + kwargs["conn_acquire_timeout"] \
             + async_buffer
    else:
      return kwargs["timeout"] + kwargs["conn_acquire_timeout"] + async_buffer
  if "timeout" in kwargs:
    return kwargs["timeout"] + async_buffer
  return 360 + async_buffer


def call_watchdog(method):
  """Decorator to execute async/sync method.

  Args:
    method (object): The function object to decorate.

  Returns:
    func: Decorated method.
  """

  @wraps(method)
  def method_call(*args, **kwargs):
    """Method to execute input method synchronously/asynchronously.

  Args:
    args (tuple): Positional arguments.
    kwargs (dict): Keyword arguments

  Returns:
    Return value of execution of input method
  """
    from concurrent.futures import TimeoutError
    obj = args[0]  # obj is the SSH object
    if getattr(obj, 'async_', None) or kwargs.get('async_'):
      method_name = method.__name__
      DEBUG("Asynchronously executing method: %s, args: %s, kwargs: %s"
            % (method_name, args, kwargs))
      timeout = get_method_timeout(method_name, **kwargs)
      attempt = 1
      retries = kwargs.get("retries") or 3
      while attempt <= retries:
        executor = ThreadPoolExecutor(max_workers=1)
        func_handle = executor.submit(method, *args, **kwargs)
        try:
          response = func_handle.result(timeout)
          return response
        except TimeoutError as e:
          DEBUG("Asynchronous execution watchdog timeout error: %s" % str(e))
          if attempt == retries:
            DEBUG("Signal the ThreadPool executor (ssh) that it should free"
                  " any resources that it is using.")
            executor.shutdown()
            exception_msg = ("Timed out after exhausting retries while "
                             "asynchronously executing method %s after %s secs"
                             % (method_name, str(timeout)))
            raise NuTestSSHTimeoutError(exception_msg, SSHCollector(obj._host))

          log_thread_stack_info()
          DEBUG("Watchdog: retry attempt %d" % attempt)
          attempt += 1
    else:
      return method(*args, **kwargs)

  return method_call


def log_thread_stack_info():
  """Dump state of thread stack in the log file"""
  curtime = datetime.now().strftime("%Y%m%d_%H%M%S")
  stack_log_path = os.path.join(os.environ["NUTEST_LOGDIR"],
                                "async_stack_dumps")
  DEBUG(stack_log_path.center(20, '*'))
  if not os.path.exists(stack_log_path):
    # Handle race condition in directory creation
    try:
      os.mkdir(stack_log_path)
    except OSError as error:
      if error.errno == errno.EEXIST:
        pass
  stack_dump_file = "stack_dump_%s_%s" % (curtime, os.getpid())
  stack_dump_file = os.path.join(stack_log_path, stack_dump_file)

  with open(stack_dump_file, "w") as _file:
    for thread, frame in sys._current_frames().items():
      _file.write("Stack for thread_id: {}\n".format(thread))
      traceback.print_stack(frame, file=_file)
      _file.write("\n\n")


INCLUDE_METHODS = ["execute", "transfer_to", "transfer_from",
                   "execute_on_interactive_channel", "transfer_fileobj_to"]


def decorate_methods(decorator):
  """ Function to decorate SSH class methods.
   Args:
      decorator (str): Decorator method

   Returns:
     Decorated class
  """

  def class_decorator(cls):
    """ Class decorator to decorate methods of the class.
    Args:
     cls (object): class object
    Returns:
     Class decorator
    """
    method_list = [func for func in dir(cls) if callable(getattr(cls, func))
                   and not func.startswith("__")]
    for method in method_list:
      if method in INCLUDE_METHODS:
        setattr(cls, method, decorator(getattr(cls, method)))
    return cls

  return class_decorator


@access_control('linux_operating_system', 'windows_operating_system',
                '__main__', 'test_ssh')
class SSH:
  """This is the main class to be used to connect to a remote host via SSH
  and execute commands."""

  def __new__(cls, *args, **kwargs):
    """Constructs a new SSH object

    Args:
      kwargs:
        host (str): The SSH host ip or hostname to connect to.
        username (str, Optional): Username to login with.
                                  Defaults to 'nutanix'.
        password (str, Optional): Password to login with.
                                  Default  to 'nutanix/4u'.
        key_file (str, Optional): Path to private SSH key. Defaults to
                                  framework/interfaces/ssh/keys/nutanix.
                                  If you don't want this module to pick up a
                                  default, pass an explicit None value for this
                                  option.
        connection_timeout (int, Optional): Connection timeout seconds.
                                  Defaults to 30 seconds.
        allow_agent(bool, Optional): Whether or not to connect to ssh agent
                                      Defaults to True.
        look_for_keys(bool, Optional): Whether or not to look for key files
                                       in ~/.ssh/ Defaults to True.
        max_connection_attempts(int, Optional): Max no.of connection attempts
          that can be attempted to establish a ssh connection.
          Authentication, timeout errors will not be exempted under this.
          Default: 3
        proxy (str, Optional): Proxy hostname or IP to connect to
        proxy_port (int, Optional): Proxy Port to login to for SSH.
                                    Defaults to None.
        proxy_user (str, Optional): Proxy User to login to for SSH.
                                    Defaults to None .
        proxy_key (str, Optional): Proxy host private key.

    Returns: _SSH object
    """
    pid = os.getpid()
    proxy = kwargs.get("proxy", None)
    cache_key = (pid,) + args + tuple(sorted(kwargs.items()))
    host = args[0] if args else kwargs.get("host")
    if cache_key not in SSH_CONNECTION_CACHE:
      # Establish new connection
      if os.environ.get("NUTEST_TELEPORT_CLUSTER", None) and \
        ManageIPs.is_hyperv_or_svm_ip(host=host):
        SSH_CONNECTION_CACHE[cache_key] = _SSH_TELEPORT(*args, **kwargs)
      elif os.environ.get("NUTEST_BASTION_HOST", None) and \
        not os.environ.get("NUTEST_TELEPORT_CLUSTER"):
        SSH_CONNECTION_CACHE[cache_key] = _SSH_BASTION_HOST(*args, **kwargs)
      elif proxy:
        SSH_CONNECTION_CACHE[cache_key] = _SSH_BASTION_HOST(*args, **kwargs)
      else:
        SSH_CONNECTION_CACHE[cache_key] = _SSH(*args, **kwargs)

    return SSH_CONNECTION_CACHE[cache_key]


@decorate_methods(call_watchdog)
class _SSH:
  """This is the private class to be used to connect to a remote host via SSH
  and execute commands. Callers should not directly call this class, rather
  access it through class 'SSH'
  """

  def __init__(self, host, username=SVM_USER, password=SVM_PASSWORD,
               key_file=KEY_FILE, allow_agent=True, look_for_keys=True,
               connection_timeout=30, max_connection_attempts=4, port=22,
               max_connections=10, max_interactive_conn=3, proxy=None,
               proxy_port=22, proxy_user="nutanix", proxy_key=None,
               pvt_key=ClusterCreds.get_pvt_key):
    # NOTE: When updating the doc here, also update the doc under SSH class too.
    """Used to initialize SSH connection to a host.

    Args:
      host (str): The SSH host ip or hostname to connect to.
      username (str, Optional): Username to login with.
                                Defaults to 'nutanix'.
      password (str, Optional): Password to login with.
                                Default  to 'nutanix/4u'.
      key_file (str, Optional): Path to private SSH key. Defaults to
                                framework/interfaces/ssh/keys/nutanix.
                                If you don't want this module to pick up a
                                default, pass an explicit None value for this
                                option.
      connection_timeout (int, Optional): Connection timeout seconds.
                                Defaults to 30 seconds.
      allow_agent(bool, Optional): Whether or not to connect to ssh agent
                                    Defaults to True.
      look_for_keys(bool, Optional): Whether or not to look for key files
                                     in ~/.ssh/ Defaults to True.
      max_connection_attempts(int, Optional): Max no.of connection attempts
        that can be attempted to establish a ssh connection.
        Authentication, timeout errors will not be exempted under this.
        Default: 3
      port (int, Optional): Port to login to. Defaults to 22.
      max_connections (int): Maximum SSH connection allowed.
        Default: 10
      max_interactive_conn (int): Maximum interactive SSH connection
        allowed.
        NOTE: This is a subset of max_connections.
          These are connections exposed to users of this class.
          If the user fails to release some connections, it may lead
          to usage of all available connections getting lost.
          As a preventive measure, we are setting a cap on it. So that,
          (max_connection-max_interactive_connection) will be available
          for use within the class.
        Default: 3
      proxy (str, Optional): Proxy hostname or IP to connect to
      proxy_user (str, Optional): proxy host user name
      proxy_key (str, Optional): proxy host private key
      proxy_port (int, Optional): Proxy Port to login to for SSH.
                                  Defaults to None.
      proxy_user (str, Optional): Proxy User to login to for SSH.
                                  Defaults to None.
      pvt_key(paramiko.key): Private key object.

    Raises:
      NuTestSSHError: if key_file is specified and it's not found.
                      when max_connections < max_interactive_conn.
    """

    # Extract required parameters.
    self._host = host
    self._username = username
    self._password = password
    self._allow_agent = allow_agent
    self._look_for_keys = look_for_keys
    self._key_file = key_file
    self._pvt_key = pvt_key
    self._max_connection_attempts = max_connection_attempts
    if self._key_file and not os.path.isfile(self._key_file):
      raise NuTestSSHError("SSH Key %s not found" % self._key_file,
                           category=ErrorCategory.USAGE)
    self._connection_timeout = connection_timeout
    self._port = port
    self._max_connections = max_connections
    self._max_interactive_conn = max_interactive_conn
    if self._max_connections < self._max_interactive_conn:
      raise NuTestSSHError("max_interactive_conn must be less than/equal to "
                           "max_session", category=ErrorCategory.USAGE)
    self._connection_pool = queue.Queue()
    self._connection_counter = SharedCounter(0)
    self._interactive_conn_counter = SharedCounter(0)

    # Filenames to use in file based locking for the connection locks.
    self._get_connection_lock_fn = \
      "get_connection_lock_file_{}_{}".format(host, id(self))
    self._get_interactive_connection_lock_fn = \
      "get_interactive_connection_lock_file_{}_{}".format(host, id(self))
    self.async_ = bool(os.environ.get('ASYNC_SSH'))
    self._proxy = None
    self._proxy_cmd = None

    if callable(self._pvt_key):
      self._pvt_key = self._pvt_key()

  def __del__(self):
    """Destructor
    """
    self.close()

  def __getstate__(self):
    """The state of the object in a form suitable to serialization using pickle

    Returns:
      dict: Object state as dictionary
    """
    # shallow copy is enough as we modify top level keys only
    state = self.__dict__.copy()
    state["_ssh"] = None
    return state

  def close_connection(self, ssh_client):
    """Close the SSH Connection. Best effort.
    Args:
      ssh_client (paramiko.SSHClient): SSHClient object.
    """
    self._connection_counter.decrement()
    try:
      ssh_client.close()
    except Exception:
      # Suppressing the exception as the closure is best effort only.
      pass

  def close_interactive_connection(self, ssh_client):
    """Close interactive connection.
    Args:
      ssh_client (paramiko.SSHClient): SSHClient object.
    """
    self._interactive_conn_counter.decrement()
    self.close_connection(ssh_client)

  def execute(self, command, retries=3, timeout=60, tty=False, background=False,
              log_response=True, conn_acquire_timeout=360,
              close_ssh_connection=False, log_command=True,
              async_=False, session_timeout=10):
    """Use this routine to execute a command over SSH on the remote host.

    Args:
      command (str): The command to execute.
      retries (int, Optional): Number of times to retries in case of failure to
                               execute the command.
                               Defaults to 3.
      timeout (timeout, Optional): Maximum time for the command to complete.
                                   Defaults to 60 seconds.
      tty (bool, Optional): If a TTY should be used on not. Defaults to True.
      background (bool, Optional): conveys if it's a background command
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
                            NOTE: We will not append '&' to background the
                            command execution. It's totally the callers
                            responsibility to handle it based on the OS.
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False. In case of exception
                                     , response will be logged irrespective
                                     of the value of log_response.
      conn_acquire_timeout (timeout, Optional): Maximum time to acquire/create
                            a connection.
                            Defaults to 360 seconds.
      close_ssh_connection (bool, Optional): Flag to set whether to close the
                                      SSH connection used for command execution.
                                      False by default.
      log_command (bool, Optional): Whether to log the command passed. Would
                                    be used while running commands including
                                    passwords. Defaults to True.
      async_ (bool, Optional): Flag to specify if ssh command execution will be
                              asynchronous. False by default.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.
    Returns:
      dict: Dict of status, stdout and stderr.

            Example of output for each element in the list:
              {'status': 0, 'stdout': u'NTNX-13AM3K010073-1-CVM\n','stderr': ''}
              A status for 0 means successful execution of the command.

    Raises:
      NuTestSSHChannelError, on failing to get SSH transport channel.
      NuTestSSHError, for failures in command execution (not the command
        failure)
      NuTestSSHTimeoutError, if the command doesn't complete within
        specified timeout
    """
    command = six.ensure_text(command, encoding='utf-8')
    if log_command:
      DEBUG("Executing '%s' on %s" % (command, self._host))
    command_doc_id = get_recorder().add_ssh_command(self._host, command)
    if os.environ.get("NUTEST_TELEPORT_CLUSTER", None):
      tty = False
    response = {'status': 1, 'stdout': '', 'stderr': ''}
    bufsize = 4096
    retry = 1
    # increasing the timeout of execute for nested environments
    if os.environ.get('NESTED_AHV') == "1":
      timeout *= 3
    while retry <= retries:
      # Get a channel to execute the command
      for _ in range(0, MAX_CHANNEL_CREATION_RETRIES):
        session = self.get_connection(timeout=conn_acquire_timeout)
        try:
          (_, chan) = self._get_channel(session, session_timeout)
          break
        except NuTestSSHChannelError as exc:
          # Create a new channel if channel failure msgs are found
          DEBUG("Hit error while trying to get channel: %s"
                "A new connection will be attempted" % str(exc))
          self.close_connection(session)
          time.sleep(1)
        except NuTestSSHError:
          self.close_connection(session)
          raise
      else:
        ERROR("Exhausted attempts to get the channel.")
        raise NuTestSSHChannelError("Failed while trying to get channel")

      # Execute the command
      try:
        if tty:
          # sudo usually requires a PTY therefore we give it one by default
          chan.get_pty(term='vt100', width=0, height=0)
        chan.settimeout(timeout)
        if log_command:
          DEBUG("%s>> '%s', timeout: %d" % (self._host, command, timeout))
        chan.exec_command(command)
        wait_time = timeout

        # Wait for exit status and thus wait for command completion
        while not chan.exit_status_ready():
          # read stdout and stderr regularly to prevent hangs when buffer gets
          # full.
          while chan.recv_ready():
            response["stdout"] += chan.recv(bufsize).decode('utf-8', 'ignore')
          while chan.recv_stderr_ready():
            response["stderr"] += chan.recv_stderr(bufsize).decode(
              'utf-8', 'ignore')
          if wait_time <= 0:
            raise socket.timeout
          time.sleep(0.1)
          wait_time -= 0.1

        # At this point, command has completed. Read any remaining output
        # which comes even beyond getting exit status due to networking
        # (delayed packets, retransmissions, ...)
        if not background:
          while True:
            temp_buffer = chan.recv(bufsize)
            # If a string of length zero is returned, the channel stream
            # has closed
            if not len(temp_buffer):
              break
            else:
              response["stdout"] += temp_buffer.decode('utf-8', 'ignore')
          # if tty is true, stderr of the command comes in stdout itself.
          while True:
            temp_buffer = chan.recv_stderr(bufsize)
            if not len(temp_buffer):
              break
            else:
              response["stderr"] += temp_buffer.decode('utf-8', 'ignore')
        else:
          while chan.recv_ready():
            response["stdout"] += chan.recv(bufsize).decode('utf-8', 'ignore')
          while chan.recv_stderr_ready():
            response["stderr"] += chan.recv_stderr(bufsize).decode(
              'utf-8', 'ignore')

        # Command exit status is ready. No more data pending in stdout or
        # stderr buffers.
        response["status"] = chan.recv_exit_status()
        break
      except socket.timeout as e:
        command = command if log_command else "*****"
        exception_msg = ("Timedout executing command %s in %s secs with error:"
                         " %s" % (command, str(timeout), repr(e)))
        DEBUG("%s<< '%s'" % (self._host, prettify(response)))
        raise NuTestSSHTimeoutError(exception_msg, SSHCollector(self._host))
      except Exception as e:
        if retry == retries:
          DEBUG("%s<< '%s'" % (self._host, prettify(response)))
          raise NuTestSSHError('Command Execution failed. %s' % str(e),
                               SSHCollector(self._host))
      finally:
        try:
          if close_ssh_connection:
            self.close_connection(session)
          else:
            self._connection_pool.put(session)
          chan.close()
        except Exception:

          # Best effort closure.
          pass
      time.sleep(5)
      retry += 1

    get_recorder().add_ssh_result(command_doc_id, response["status"],
                                  response["stdout"], response["stderr"])
    if log_response:
      DEBUG("%s<< '%s'" % (self._host, prettify(response)))
    return response

  def close(self):
    """Close the SSH Connections. Best effort.
    """
    while not self._connection_pool.empty():
      self.close_connection(self._connection_pool.get())

  def get_connection(self, timeout=360):
    """This method returns ssh client handle

    STEPS:
      1. The first thread entering this method will get the lock.
      2. Tries to get a SSH connection object.
         a. tries to get from connection pool,
            if available (Returns the connection)
         b. If number of sessions in current use reaches max_connections,
            continues on STEP 2.
            Otherwise creates new SSH connection and returns new SSH connection
    Args:
      timeout (int): maximum wait time to acquire a connection.

    Raises:
      NuTestSSHConnectionError: If failed to create/acquire a connection
        with the timeout interval.

    Returns:
      (paramiko.SSHClient): ssh_client object
    """
    wait_time = timeout
    start_time = time.time()
    # We don't want to impose a lock timeout here. Some test workflows which
    # power off the hypervisor for extended periods of time will cause the
    # lock timeout to expire which is expected.
    with lock_file(self._get_connection_lock_fn, poll_interval=.5):
      while True:
        # Check for usable SSHClients in the connection pool.
        while not self._connection_pool.empty():
          ssh_obj = self._connection_pool.get()
          transport = ssh_obj.get_transport()
          # If the transport is active, then the SSHClient is usable.
          if transport and transport.is_active():
            return ssh_obj
          else:
            # Close the SSHClient and reduce the connection count.
            try:
              ssh_obj.close()
            except Exception:
              pass
            finally:
              self._connection_counter.decrement()
          # Check for timeout.
          if time.time() - start_time >= wait_time:
            raise NuTestSSHConnectionError(
              "Timed out getting an SSHClient from connection pool for %s"
              % self._host)

        # The pool is empty, so check if there are too many existing connections
        # in the process.
        if self._connection_counter.value() >= self._max_connections:
          if time.time() - start_time >= wait_time:
            raise NuTestSSHConnectionError(
              "Failed to get SSH Connection to the host : %s" % self._host)
          time.sleep(1)
        else:
          # Create a new SSHClient.
          return self._get_connection()

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def get_interactive_connection(self, timeout=360):
    """This method returns an ssh client to be used for interactive channels
    Args:
      timeout (int): maximum wait time to acquire a connection.
    Returns:
      (paramiko.SSHClient): ssh_client object
    Raises:
      NuTestSSHConnectionError: If failed to get interactive connection
        with the timeout interval.
    """
    start_time = time.time()
    with lock_file(self._get_interactive_connection_lock_fn, poll_interval=1):
      while self._interactive_conn_counter.value() >= \
        self._max_interactive_conn:
        time.sleep(1)
        timeout -= 1
        if timeout <= 0:
          raise NuTestSSHConnectionError("Failed to get interactive_connection"
                                         " to host : %s ", self._host)
      self._interactive_conn_counter.increment()

    # Adding a buffer of 30 seconds in case if 'timeout' is reached 0
    if timeout < 30:
      timeout = time.time() - start_time + 30

    return self.get_connection(timeout=timeout)

  def release_connection(self, ssh_client):
    """release the SSH client handle to be added to pool
    Args:
      ssh_client (paramiko.SSHClient): ssh_client object
    """
    self._connection_pool.put(ssh_client)

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def release_interactive_connection(self, ssh_client):
    """release the SSH client handle to be added to pool.
    Args:
      ssh_client (paramiko.SSHClient): ssh_client object
    """
    self._interactive_conn_counter.decrement()
    self.release_connection(ssh_client)

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def get_interactive_channel(self, session):
    """Get an interactive ssh channel.

    Args:
      session (paramiko.SSHClient): ssh_client object

    Returns:
      (object): The channel object.

    Raises:
      NuTestSSHChannelError: When channel specific exception is encountered.
      NuTestSSHError: When failed to acquire channel even after
                      MAX_CHANNEL_CREATION_RETRIES.
    """
    # List of Channel Failure messages
    no_channel_msgs = ['Failed to open session',
                       'Timeout openning channel',
                       'Connection reset by peer']

    # List of Session Failure messages
    no_session_msgs = ['Administratively prohibited', 'Unable to open channel']

    for _ in range(0, MAX_CHANNEL_CREATION_RETRIES):
      try:
        return session.invoke_shell()
      except Exception as e:
        exc = e
        if any(map(lambda msg, exc=exc: msg in str(exc), no_channel_msgs)):
          DEBUG("While trying to get a channel, we hit channel specific "
                "errors: %s" % str(exc))
          raise NuTestSSHChannelError(str(exc))

        if not any(map(lambda msg, exc=exc: msg in str(exc), no_session_msgs)):
          DEBUG("While trying to get a channel, we hit: %s" % str(exc))
          raise NuTestSSHChannelError(str(exc))

        else:
          # Lets retry for any session failure messages
          time.sleep(1)
    raise NuTestSSHError("Error while getting interactive channel after " +
                         "{max} retries: "
                         .format(max=MAX_CHANNEL_CREATION_RETRIES) +
                         "{error}".format(error=exc),
                         SSHCollector(self._host))

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def send_to_interactive_channel(self, command, interactive_channel,
                                  timeout=30, line_separator="\n",
                                  log_command=True):
    """Send command to an interactive SSH channel on the remote host.

    Args:
      command (str): The command to execute.
      interactive_channel (object): The interactive channel to execute the
                            command upon
      timeout (timeout, Optional): Maximum time for the command to be sent
                                   Defaults to 30 seconds.
      line_separator (str, Optional): line separator character
                            (equivalent of pressing Enter button for command)
                            For Windows, it is \r\n
      log_command (bool, Optional): Whether to log the command passed. Would
                                    be used while running commands including
                                    passwords. Defaults to False.

    Raises:
      NuTestSSHTimeoutError: When timed out while executing the conmmand.
      NuTestSSHError: When failed while executing the command.

    Usage:
    ssh_client = SSH(host=...)
    ichannel = ssh_client.get_interactive_channel()
    ssh_client.send_to_interactive_channel(command='term len 0',
                                           interactive_channel=ichannel)
    """
    if log_command:
      DEBUG("{host}>> '{command}', timeout: {timeout}"
            .format(host=self._host, command=command, timeout=timeout))
    wait_time = timeout
    poll_frequency = 0.1
    try:
      interactive_channel.settimeout(timeout)
      while not interactive_channel.send_ready():
        if wait_time <= 0:
          command = command if log_command else "****"
          raise NuTestSSHTimeoutError("Command {cmd} timed out in {timeout} " +
                                      "seconds.".format(cmd=command,
                                                        timeout=timeout))
        time.sleep(poll_frequency)
        wait_time -= poll_frequency

      # At this point, the channel should be ready
      interactive_channel.send("{command}{sep}".format(command=command,
                                                       sep=line_separator))
    except Exception as e:
      raise NuTestSSHError("Error while sending command to interactive " +
                           "channel: {error}".format(error=e),
                           SSHCollector(self._host))

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def receive_from_interactive_channel(self, interactive_channel):
    """Receive response from an interactive SSH channel on the remote host.

    Args:
      interactive_channel (object): The interactive channel to read the
                            response from
    Returns:
      str: response from the channel

    Raises:
      NuTestSSHError

    Usage:
    ssh_client = SSH(host=...)
    ichannel = ssh_client.get_interactive_channel()
    ssh_client.receive_from_interactive_channel(interactive_channel=ichannel)
    """
    response = ""
    bufsize = 4096
    try:
      while interactive_channel.recv_ready():
        response_recv = interactive_channel.recv(bufsize)
        if isinstance(response_recv, bytes):
          response_recv = response_recv.decode()
        response += str(response_recv)
    except Exception as e:
      raise NuTestSSHError("Error while receiving response from interactive " +
                           "channel: {error}, Response: '{response}'"
                           .format(error=e, response=response),
                           SSHCollector(self._host))
    DEBUG("{host}>> response: '{response}'"
          .format(host=self._host, response=response))
    return response

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def execute_on_interactive_channel(self, command, interactive_channel,
                                     pattern, timeout=30, line_separator="\n",
                                     re_flags=0, async_=False):
    """Execute command over an interactive SSH channel on the remote host.

    Args:
      command (str): The command to execute.
      interactive_channel (object): The interactive channel to execute the
                            command upon
      pattern (str): Regular expression to be matched in the received response
      timeout (timeout, Optional): Maximum wait time for the pattern to match
                            between command sent and response received
                            Defaults to 30 seconds.
      line_separator (str, Optional): line separator character
                            (equivalent of pressing Enter button for command)
                            For Windows, it is \r\n
      re_flags (integer, Optional): Python standard regular expression flags
      async_ (bool, Optional): Flag to specify if ssh command execution will be
                              asynchronous. False by default.

    Returns:
      object: iterator over all non-overlapping matches for the regular
           expression pattern in the response

    Raises:
      NuTestSSHTimeoutError
      NuTestSSHError

    Usage:
    ssh_client = SSH(host=...)
    ichannel = ssh_client.get_interactive_channel()
    matches = ssh_client.execute_on_interactive_channel(command='term len 0',
              interactive_channel=ichannel, pattern=r'(foo.*bar)')
    for match in matches:
      print(match.group(0))
    """
    DEBUG("{host}>> '{command}', timeout: {timeout}"
          .format(host=self._host, command=command, timeout=timeout))

    try:
      response = ""
      self.send_to_interactive_channel(command=command,
                                       interactive_channel=interactive_channel,
                                       timeout=timeout,
                                       line_separator=line_separator)
      regex = re.compile(pattern, re_flags)
      wait_time = timeout
      poll_frequency = 0.1
      while wait_time > 0:
        response += self.receive_from_interactive_channel(
          interactive_channel=interactive_channel)
        if re.search(regex, response):
          DEBUG("response>> '{response}'".format(response=response))
          return regex.finditer(response)
        time.sleep(poll_frequency)
        wait_time -= poll_frequency
      else:
        raise NuTestSSHTimeoutError("Command {cmd} ".format(cmd=command) +
                                    "timed out in {timeout} seconds. "
                                    .format(timeout=timeout) +
                                    "Response: '{response}'"
                                    .format(response=response))
    except Exception as e:
      raise NuTestSSHError("Error while executing interactive command: " +
                           "{error}, Response: '{response}'"
                           .format(error=e, response=response),
                           SSHCollector(self._host))

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def transfer_from(self, remote_path, local_path, retries=3, timeout=360,
                    async_=False, session_timeout=10):
    """Transfers a file from remote server

    Args:
      remote_path (str): Remote path of the file to be transferred.
      local_path (str): Local path of the file to be copied.
      retries(int, optional): The number of retries. Defaults to 3.
      timeout(int, optional): Timeout seconds. Defaults to 360.
      async_ (bool, Optional): Flag to specify if ssh command execution will be
                              asynchronous. False by default.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.

    Returns:
      None

    Raises:
      NuTestSSHError
    """
    retry = 1
    while retry <= retries:
      (ssh_obj, transport, channel) = self._get_connection_components(
        timeout=timeout, session_timeout=session_timeout)
      transfer_doc_id = get_recorder().add_inbound_scp_record(
        self._host, remote_path, local_path)
      try:
        scpclient = SCPClient(transport,
                              socket_timeout=timeout)
        # Combine stdout and stderr so that output of both stdout and stderr
        # is read otherwise only stdout is read and stderr is not read which
        # causes stderr buffer to become full and cause scp command to hang.
        DEBUG("Combine channel stdout and stderr")
        channel.set_combine_stderr(True)
        scpclient.channel = channel
        ret = scpclient.get(remote_path, local_path, recursive=True,
                            preserve_times=True)
        DEBUG("Transferred '%s' (remote) to '%s' (local)" % (remote_path,
                                                             local_path))
        return ret
      except Exception as e:
        DEBUG("Unable to transfer '%s' to %s: '%s'" % (remote_path,
                                                       local_path, str(e)))
        if retry == retries:
          raise NuTestSSHError('Copy Error. %s' % str(e),
                               SSHCollector(self._host))
        DEBUG("Retrying file transfer...")
      finally:
        try:
          self.release_connection(ssh_obj)
          scpclient.close()
        except Exception:

          # Best effort closure
          pass
        get_recorder().add_scp_result(transfer_doc_id)
      retry += 1

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def transfer_to(self, local_path, remote_path, retries=3, timeout=360,
                  async_=False, perm=None, session_timeout=10,
                  close_ssh_connection=False):
    """Transfers a local file to remote server

    Args:
      local_path (str): Local path of the file to be transferred.
      remote_path (str): Remote path of the file.
      retries(int, optional): The number of retries. Defaults to 3.
      timeout(int, optional): Timeout seconds. Defaults to 360.
      async_ (bool, Optional): Flag to specify if ssh command
      execution should be asynchronous. False by default.
      perm (str): Permission to be set on remote file.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.
      close_ssh_connection (bool, Optional): Flag to set whether to close the
                                SSH connection used for command execution.
                                False by default.

    Returns:
      None

    Raises:
      NuTestSSHError
    """
    if not os.path.exists(local_path):
      msg = "File does not exist: %s" % local_path
      raise NuTestSSHError(msg, category=ErrorCategory.USAGE)

    retry = 1
    while retry <= retries:
      (ssh_obj, transport, channel) = self._get_connection_components(
        timeout=timeout, session_timeout=session_timeout)
      transfer_doc_id = get_recorder().add_outbound_scp_record(
        self._host, local_path, remote_path)
      try:
        scpclient = SCPClient(transport,
                              socket_timeout=timeout)
        scpclient.channel = channel
        ret = scpclient.put(local_path, remote_path, recursive=True,
                            preserve_times=True)
        DEBUG("Transferred '%s' (local) to '%s' (remote)" % (local_path,
                                                             remote_path))
        return ret
      except Exception as e:
        DEBUG("Unable to transfer '%s' to %s: '%s'" % (local_path,
                                                       remote_path, str(e)))
        if retry == retries:
          raise NuTestSSHError('Copy Error. %s' % str(e),
                               SSHCollector(self._host))
        DEBUG("Retrying file transfer...")
      finally:
        try:
          if close_ssh_connection:
            self.close_connection(ssh_obj)
          else:
            self.release_connection(ssh_obj)
          scpclient.close()
        except Exception:

          # Best effort closure.
          pass
        get_recorder().add_scp_result(transfer_doc_id)
      retry += 1

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def transfer_fileobj_to(self, fileobj, remote_path, retries=3, timeout=360,
                          async_=False, session_timeout=10, **kwargs):
    """Transfers a file-like object to remote server.

    Args:
      fileobj (file-like): An open file-like object.
      remote_path (str): Remote path on the server to transfer the file to.
      retries(int, optional): Number of retries. Defaults to 3.
      timeout(int, optional): Timeout in seconds. Defaults to 360.
      async_ (bool, Optional): Flag to specify if ssh command
      execution should be asynchronous. False by default.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.

    Raises:
      NuTestSSHError
    """
    for attempt in range(1, retries + 1):
      DEBUG("Transfer Attempt %s: '%s' to '%s'"
            % (attempt, fileobj, remote_path))
      (ssh, transport, channel) = self._get_connection_components(
        timeout=timeout, session_timeout=session_timeout)
      transfer_doc_id = get_recorder().add_outbound_scp_record(
        self._host, str(fileobj), remote_path)
      try:
        scp = SCPClient(transport, socket_timeout=timeout)
        scp.channel = channel
        scp.putfo(fileobj, remote_path, **kwargs)
        DEBUG("Transferred '%s' to '%s'" % (fileobj, remote_path))
        break
      except Exception as exc:
        DEBUG("Unable to transfer '%s' to '%s': '%s'"
              % (fileobj, remote_path, str(exc)))
        if attempt == retries:
          raise NuTestSSHError("Copy Error: %s" % str(exc))
      finally:
        try:
          self.release_connection(ssh)
          scp.close()
        except Exception:
          # Best effort closure.
          pass
        get_recorder().add_scp_result(transfer_doc_id)

  def _get_connection(self):
    """Initiates new SSH connection

    Returns:
      (paramiko.SSHClient): ssh_client object

    Raises:
      NuTestSSHConnectionError, NuTestSSHConnectionTimeoutError
    """
    max_attempt = self._max_connection_attempts

    # Open new SSH client
    ssh_obj = paramiko.SSHClient()

    # Disable host key check
    ssh_obj.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_obj.set_log_channel('')

    # Initiate the SSH connection
    connection_attempt = 1
    while connection_attempt <= max_attempt:
      DEBUG("Trying to connect to %s. Attempt: %s" %
            (self._host, connection_attempt))
      try:
        proxy = None
        if self._proxy_cmd:
          proxy = ProxyCommand(self._proxy_cmd)
        ssh_obj.connect(
          self._host,
          username=self._username,
          key_filename=self._key_file,
          password=self._password,
          timeout=self._connection_timeout,
          port=self._port,
          allow_agent=self._allow_agent,
          look_for_keys=self._look_for_keys,
          banner_timeout=600,
          sock=proxy,
          pkey=self._pvt_key
        )
        ssh_obj.get_transport().set_keepalive(5)
        DEBUG("Connected to host %s" % self._host)
        break
      except AuthenticationException as e:
        ERROR("Authentication Error. Credentials Used : %s,%s" %
              (self._username, self._password))
        raise NuTestSSHAuthenticationError('Authentication Error. %s' % str(e))
      except socket.timeout as e:
        if connection_attempt == max_attempt:
          raise NuTestSSHConnectionTimeoutError(
            'Connection Timeout due to socket timeout. %s' %
            str(e), SSHCollector(self._host))
      except Exception as e:
        if connection_attempt == max_attempt:
          raise NuTestSSHConnectionError('Connection Error. %s' % str(e),
                                         SSHCollector(self._host))
        DEBUG("Hit error: %s. Continuing with retry" % str(e))
      connection_attempt += 1
      time.sleep(10)

    # We have successfuly created a connection. Incrementing
    # the connection counter.
    self._connection_counter.increment()
    return ssh_obj

  def _get_channel(self, session, session_timeout=10):
    """Get the SSH transport channel

    Args:
      session (paramiko.SSHClient): ssh_client object
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.

    Returns:
      (object): The channel object.

    Raises:
      NuTestSSHError
    """
    # List of Channel Failure messages
    no_channel_msgs = ['Failed to open session',
                       'Timeout openning channel',
                       'Connection reset by peer']

    # List of Session Failure messages
    no_session_msgs = ['Administratively prohibited', 'Unable to open channel']

    e = None
    for _ in range(0, MAX_CHANNEL_CREATION_RETRIES):
      try:
        transport = session.get_transport()
        if transport:
          chan = transport.open_session(timeout=session_timeout)
          return (transport, chan)
        else:
          # Lets retry to get the transport
          e = 'Unable to get transport'
          time.sleep(1)
      except Exception as e:
        exc = e
        if any(map(lambda msg, exc=exc: msg in str(exc), no_channel_msgs)):
          DEBUG("While trying to get a channel, we hit channel specific "
                "errors: %s" % str(exc))
          raise NuTestSSHChannelError(str(exc))

        if not any(map(lambda msg, exc=exc: msg in str(exc), no_session_msgs)):
          DEBUG("While trying to get a channel, we hit: %s" % str(exc))
          raise NuTestSSHChannelError(str(exc))

        else:
          # Lets retry for any session failure messages
          time.sleep(1)

    msg = "Failed to open session: " + str(exc)
    raise NuTestSSHError(msg, SSHCollector(self._host))

  # This method is added just to avoid code duplication in transfer_to
  # transfer_to, execute and other operations
  def _get_connection_components(self, timeout=360, session_timeout=10):
    """Give a proper connection object with valid channel.
    Args:
      timeout (int): maximum wait time to acquire a connection.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.
    Returns:
      tuple: (ssh_obj, transport, channel)
    """
    for _ in range(0, 15):
      session = self.get_connection(timeout=timeout)
      try:
        (transport, chan) = self._get_channel(session, session_timeout)
        return session, transport, chan
      except NuTestSSHChannelError as exc:
        # Create a new channel if channel failure msgs are found
        DEBUG("Hit error while trying to get channel: %s"
              "A new connection will be attempted" % str(exc))
        self.close_connection(session)
        time.sleep(1)
      except NuTestSSHError:
        self.close_connection(session)
        raise


class SSHCollector:
  """This is the log collector for this module"""

  def __init__(self, host=None):
    """Constructor for the log collector class.

    Args:
      host (str): Host name or IP.

    Returns:
      None
    """
    self._host = host

  def collect(self):
    """Implements the collection of ping traces.
    """
    if self._host:
      ping(self._host, use_nmap=True, retries=1)


def prettify(response):
  """Prettify the response for the debug messages.

    Args:
      response (dict or string): SSH command response.

    Returns:
      output (str): Prettified output
  """

  output = copy.deepcopy(response)
  try:
    output['stdout'] = json.loads(output['stdout'])
  except ValueError:
    fmt = "  %s: %s"
    output = ',\n'.join(fmt % (key, val) for (key, val) in output.items())
    return '{\n' + output + '}'
  return json.dumps(output, indent=2)


@decorate_methods(call_watchdog)
class _SSH_BASTION_HOST(_SSH):
  """This is the main class to be used to connect to a remote host via SSH
     bastion host and execute commands."""

  def __init__(self, *args, **kwargs):
    """Initializer method to set up bastion host."""
    super(_SSH_BASTION_HOST, self).__init__(*args, **kwargs)
    proxy = kwargs.get("proxy", None)
    port = kwargs.get("port", 22)
    if not proxy:
      proxy = os.environ.get("NUTEST_BASTION_HOST")
    if proxy:
      proxy_user = kwargs.get("proxy_user")
      if not proxy_user:
        proxy_user = os.environ.get("NUTEST_BASTION_HOST_USER", "nutanix")
      proxy_port = kwargs.get("proxy_port")
      if not proxy_port:
        proxy_port = int(os.environ.get("NUTEST_BASTION_HOST_PORT", 22))
      proxy_key = kwargs.get("proxy_key", None)
      if not proxy_key:
        proxy_key = os.environ.get("NUTEST_BASTION_HOST_PVT_KEY")
    if proxy:
      if proxy_key:
        self._proxy_cmd = \
          "ssh -i %s -o StrictHostKeyChecking=no %s@%s -p %s -W %s:%s" % \
          (proxy_key, proxy_user, proxy, proxy_port,
           self._host, port)
      else:
        self._proxy_cmd = "ssh %s@%s -p %s -W %s:%s" % \
                          (proxy_user, proxy, proxy_port,
                           self._host, port)


@decorate_methods(call_watchdog)
class _SSH_TELEPORT(_SSH):
  """ SSH through teleport. """

  def __init__(self, *args, **kwargs):
    """Initializer method to set up bastion host."""
    super(_SSH_TELEPORT, self).__init__(*args, **kwargs)
    self._proxy = None
    self._pvt_key = None

  # pylint: disable=no-self-use
  def tsh_transfer_to(self, local_path,
                      remote_path, perm="755", **kwargs):
    """Transfers a local file to remote server using tsh protocol.

    Args:
      local_path (str): Local path of the file to be transferred.
      remote_path (str): Remote path of the file.
      perm (str, Optional): Target file permissions.

    Returns:
      None

    Raises:
      Exception if checksum computation oe file transfer fails.
    """
    from framework.operating_systems.operating_system.linux_operating_system \
      import LinuxOperatingSystem
    local_paths, remote_paths = [], []
    remote_file_name = None
    if os.path.isdir(local_path):
      # If the source path is a directory, build a list of files in source path
      # dir and its subdirs.
      for root, folders, files in os.walk(local_path):
        for elem in folders + files:
          l_path = os.path.join(root, elem)
          if os.path.isdir(l_path):
            sub_path = l_path.replace(local_path, "").strip("/")
            # create the subdirectory on the remote host
            r_path = os.path.join(remote_path, sub_path)
            DEBUG("Creating remote path: %s" % r_path)
            cmd = "tsh ssh -i %s --proxy=%s %s@node-%s mkdir -p %s" \
                  % (os.environ["NUTEST_IDENTITY_FILE_PATH"],
                     os.environ["NUTEST_TELEPORT_CLUSTER"],
                     os.environ.get("NUTEST_BASTION_HOST_USER", "nutanix"),
                     self._host, r_path)
            response = LinuxOperatingSystem.local_execute(cmd)
            if response["status"] != 0:
              raise Exception("Creation of sub directory %s failed with"
                              " error %d" % (r_path, response["status"]))
            DEBUG("Continue path build")
            continue
          sub_path = l_path.replace(local_path, "").strip("/")
          r_path = os.path.join(remote_path, sub_path)
          local_paths.append(l_path)
          remote_paths.append(r_path)
    else:
      remote_file_name = os.path.basename(local_path)
      local_paths.append(local_path)
      remote_paths.append(remote_path)
    if not perm:
      perm = "755"
    for local_path, remote_path in zip(local_paths, remote_paths):
      ext = os.path.splitext(local_path)[-1].lower()
      if ext == ".pyc":
        DEBUG("Excluding transfer of .pyc file: %s" % local_path)
        continue
      response = LinuxOperatingSystem.local_execute("sha256sum %s" % local_path)
      if response["status"] == 0:
        sha256sum = response["stdout"].split()[0]
        user = kwargs.get("user", None)
        if not user:
          user = os.environ.get("NUTEST_BASTION_HOST_USER", "nutanix")
        sudo = "sudo"
        if user == "root":
          sudo = ""
        DEBUG("Checksum for file %s: %s" % (local_path, sha256sum))
        cmd = "cat %s | tsh ssh -i %s --proxy=%s %s@node-%s %s %s %s %s %s" \
              % (local_path,
                 os.environ["NUTEST_IDENTITY_FILE_PATH"],
                 os.environ["NUTEST_TELEPORT_CLUSTER"],
                 user, self._host, sudo,
                 TSH_TRANSFER_SCRIPT_PATH,
                 remote_path, sha256sum, perm)
        if remote_file_name:
          cmd += " %s" % remote_file_name
        response = LinuxOperatingSystem.local_execute(cmd)
        if response["status"] != 0:
          raise Exception("Transferring file through tsh protocol failed with"
                          " error code %d" % response["status"])
      else:
        raise Exception("Checksum computation for file %s failed with "
                        "error code %d"
                        % (local_path, response["status"]))

  def transfer_to(self, local_path, remote_path, retries=5, timeout=360,
                  async_=False, perm="755", session_timeout=10, **kwargs):
    """Transfers a local file to remote server

    Args:
        local_path (str): Local path of the file to be transferred.
        remote_path (str): Remote path of the file.
        retries(int, optional): The number of retries. Defaults to 3.
        timeout(int, optional): Timeout seconds. Defaults to 360.
        async_ (bool, Optional): Flag to specify if ssh command execution
                                should be asynchronous. False by default.
        perm (str, Optional): Target file permissions.
        session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.

      Returns:
        None

      Raises:
        NuTestSSHError
    """
    if not os.path.exists(local_path):
      msg = "File does not exist: %s" % local_path
      raise NuTestSSHError(msg, category=ErrorCategory.USAGE)

    retry = 1
    while retry <= retries:
      transfer_doc_id = get_recorder().add_outbound_scp_record(
        self._host, local_path, remote_path)
      try:
        ret = self.tsh_transfer_to(local_path, remote_path,
                                   perm=perm, **kwargs)
        return ret
      except Exception as e:
        DEBUG("Unable to transfer '%s' to %s: '%s'" % (local_path,
                                                       remote_path, str(e)))
        if retry == retries:
          raise NuTestSSHError('Copy Error. %s' % str(e),
                               SSHCollector(self._host))
        time.sleep(1)
        DEBUG("Retrying file transfer...")
      finally:
        get_recorder().add_scp_result(transfer_doc_id)
      retry += 1

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def transfer_fileobj_to(self, fileobj, remote_path, retries=3, timeout=360,
                          async_=False, session_timeout=10, **kwargs):
    """Transfers a file-like object to remote server.

    Args:
      fileobj (file-like): An open file-like object.
      remote_path (str): Remote path on the server to transfer the file to.
      retries(int, optional): Number of retries. Defaults to 3.
      timeout(int, optional): Timeout in seconds. Defaults to 360.
      async_ (bool, Optional): Flag to specify if ssh command execution
                               should be asynchronous. False by default.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.

    Returns:
      None

    Raises:
      NuTestSSHError
    """
    return self.transfer_to(fileobj.name, remote_path, retries=retries,
                            timeout=timeout, async_=async_,
                            session_timeout=session_timeout,
                            **kwargs)

  def tsh_transfer_from(self, remote_path, local_path):
    """Transfers a file from remote server using tsh protocol

    Args:
      remote_path (str): Remote path of the file to be transferred.
      local_path (str): Local path of the file to be copied.`

    Returns:
      None

    Raises:
      NuTestSSHError
    """
    from framework.operating_systems.operating_system.linux_operating_system \
      import LinuxOperatingSystem
    cmd = "tsh scp -r -i %s --proxy=%s %s@node-%s:%s  %s" \
          % (os.environ["NUTEST_IDENTITY_FILE_PATH"],
             os.environ["NUTEST_TELEPORT_CLUSTER"],
             os.environ.get("NUTEST_BASTION_HOST_USER", "nutanix"),
             self._host,
             remote_path,
             local_path)
    response = LinuxOperatingSystem.local_execute(cmd)
    if response["status"] != 0:
      DEBUG("Transferring files from tsh protocol failed with error message %s"
            % response["stderr"])
      raise Exception("Transferring file from tsh protocol failed with"
                      " error code %d" % response["status"])

  def transfer_from(self, remote_path, local_path, retries=5, timeout=360,
                    async_=False, session_timeout=10):
    """Transfers a file from remote server

    Args:
      remote_path (str): Remote path of the file to be transferred.
      local_path (str): Local path of the file to be copied.
      retries(int, optional): The number of retries. Defaults to 3.
      timeout(int, optional): Timeout seconds. Defaults to 360.
      async_ (bool, Optional): Flag to specify if ssh command execution will be
                              asynchronous. False by default.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.

    Returns:
      None

    Raises:
      NuTestSSHError
    """
    retry = 1
    while retry <= retries:
      transfer_doc_id = get_recorder().add_inbound_scp_record(
        self._host, remote_path, local_path)
      try:
        ret = self.tsh_transfer_from(remote_path, local_path)
        DEBUG("Transferred '%s' (remote) to '%s' (local)" % (remote_path,
                                                             local_path))
        return ret
      except Exception as e:
        DEBUG("Unable to transfer '%s' to %s: '%s'" % (remote_path,
                                                       local_path, str(e)))
        if retry == retries:
          raise NuTestSSHError('Copy Error. %s' % str(e),
                               SSHCollector(self._host))
        time.sleep(1)
        DEBUG("Retrying file transfer...")
      finally:
        get_recorder().add_scp_result(transfer_doc_id)
      retry += 1

  def _get_connection(self):
    """Initiates new SSH connection

    Returns:
      (paramiko.SSHClient): ssh_client object

    Raises:
      NuTestSSHConnectionError, NuTestSSHConnectionTimeoutError
    """
    max_attempt = self._max_connection_attempts

    # Open new SSH client
    ssh_obj = paramiko.SSHClient()

    # Disable host key check
    ssh_obj.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_obj.set_log_channel('')

    proxy = os.environ.get("NUTEST_BASTION_HOST")
    if proxy and os.environ.get("NUTEST_BASTION_HOST_PORT"):
      proxy_port = int(os.environ.get("NUTEST_BASTION_HOST_PORT"))
    if proxy and os.environ.get("NUTEST_BASTION_HOST_USER", "nutanix"):
      proxy_user = os.environ.get("NUTEST_BASTION_HOST_USER", "nutanix")
    tsh_path = distutils.spawn.find_executable('tsh')  # pylint: disable=no-member
    with tele_proxy_lock:
      DEBUG("Instantiating paramiko proxy command class under lock for"
            " host %s." % self._host)
      self._proxy = ProxyCommand('%s proxy ssh -i %s --proxy=%s'
                                 ' %s@node-%s:%s'
                                 % (tsh_path,
                                    os.environ["NUTEST_IDENTITY_FILE_PATH"],
                                    proxy,
                                    proxy_user,
                                    self._host,
                                    proxy_port))
    self._port = proxy_port
    if not self._pvt_key:
      pkey = RSAKey(filename=os.environ["NUTEST_RSA_KEY_PATH"])
      pkey.load_certificate(open(os.environ["NUTEST_CERT_PATH"]).read())
      self._pvt_key = pkey
    # Initiate the SSH connection
    connection_attempt = 1
    while connection_attempt <= max_attempt:
      DEBUG("Trying to connect to %s. Attempt: %s" %
            (self._host, connection_attempt))
      try:
        ssh_obj.connect(
          self._host,
          username=self._username,
          timeout=self._connection_timeout,
          port=self._port,
          banner_timeout=600,
          sock=self._proxy,
          pkey=self._pvt_key,
          disabled_algorithms={'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']}
        )
        ssh_obj.get_transport().set_keepalive(5)
        DEBUG("Connected to host %s" % self._host)
        break
      except AuthenticationException as e:
        raise NuTestSSHAuthenticationError('Authentication Error. %s' % str(e))
      except socket.timeout as e:
        if connection_attempt == max_attempt:
          raise NuTestSSHConnectionTimeoutError(
            'Connection Timeout due to socket timeout. %s' %
            str(e), SSHCollector(self._host))
      except Exception as e:
        if connection_attempt == max_attempt:
          raise NuTestSSHConnectionError('Connection Error. %s' % str(e),
                                         SSHCollector(self._host))
        DEBUG("Hit error: %s. Continuing with retry" % str(e))
      connection_attempt += 1
      time.sleep(10)

    # We have successfuly created a connection. Incrementing
    # the connection counter.
    self._connection_counter.increment()
    return ssh_obj
