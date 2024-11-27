"""Python module for initiating and executing the RPC calls on cluster
using XML RPC server.

Copyrights (c) Nutanix Inc. 2016

Authors: sunil.goyal@nutanix.com
         sudharshan.dm@nutanix.com
"""
# pylint: disable=broad-except
# pylint: disable=import-outside-toplevel
# pylint: disable=no-else-return, no-else-raise
# pylint: disable=global-statement, no-member
# pylint: disable=redefined-builtin

import errno
import socket
import time
import threading
import os

from functools import wraps
from concurrent.futures import ThreadPoolExecutor,\
  TimeoutError

import framework.interfaces.consts as interface_consts

from framework.entities.vm.nos_vm import NOSVM
from framework.exceptions.interface_error import NuTestRPCError
from framework.interfaces.rpc.rpc_proxy import Server
from framework.lib.nulog import INFO, DEBUG, WARN, ERROR
from framework.lib.package_handler import PackageHandler
from framework.lib.utils import get_nutest_run_id
from framework.operating_systems.file_path.file_path import FilePath
from framework.exceptions.nutest_error import NuTestError
from framework.exceptions.interface_error import NuTestRPCTimeoutError

# This path is respective to the NuTest execution environment.
DEFAULT_SOURCE_RPC_DIR_PATH = \
  FilePath(PackageHandler.get_resource_path("framework/interfaces/rpc"))
SERVER_FILE_NAME = os.path.basename(PackageHandler.get_resource_path(
  os.path.join('framework', 'interfaces', 'rpc', 'rpc_server.py')))
ENV_FILE_NAME = os.path.basename(PackageHandler.get_resource_path(
  os.path.join('framework', 'interfaces', 'rpc', 'nutest_env.py')))

# This path is respective to the target CVM environment.
DEFAULT_TARGET_RPC_DIR_PATH = \
  FilePath(FilePath.LINUX, FilePath.ROOT, "home", "nutanix", "rpc")

# Path where all rpc_helper files resides
DEFAULT_SOURCE_RPC_HELPER_DIR_PATH = \
  FilePath(PackageHandler.get_resource_path("framework/lib/rpc_helpers"))

# Default port where server listens to.
DEFAULT_SERVER_PORT = 3300

RPC_SETUP_LOG = "/home/nutanix/rpc/rpc_setup.log"

MAX_RETRIES = 5

def call_watchdog(method):
  """Decorator to execute async/sync method.

  Args:
    method (object): The function object to decorate.

  Returns:
    func: Decorated method.
  """

  @wraps(method)
  def method_call(self, *args, **kwargs):
    """Method to execute input method synchronously/asynchronously.

  Args:
    args (tuple): Positional arguments.
    kwargs (dict): Keyword arguments

  Returns:
    Return value of execution of input method
  """
    DEBUG("RPC watchdog: method_call: args: %s: kwargs: %s" % (args, kwargs))
    func_name = args[0]  # rpc function to be executed
    local_args = tuple(list(args)[1:])
    if not self.synch or not kwargs.get('async'):
      method_name = method.__name__
      DEBUG("Asynchronously executing method: %s, args: %s, kwargs: %s"
            % (method_name, args, kwargs))
      DEBUG("RPC method timeout=%s" % self.timeout)
      attempt, retries = 1, 2
      while attempt <= retries:
        executor = ThreadPoolExecutor(max_workers=1)
        func_handle = executor.submit(method, self, func_name,
                                      *local_args, **kwargs)
        try:
          response = func_handle.result(self.timeout)
          return response
        except TimeoutError as exc:
          ERROR("Asynchronous execution of method %s through watchdog"
                " timed out with error: %s" % (func_name, str(exc)))
          DEBUG("Signal the ThreadPool executor (rpc timeout) that it should"
                " free any resources that it is using.")
          executor.shutdown()
          # we do not want to re-execute a non-idempotent call.
          raise NuTestRPCTimeoutError(
            "Method %s execution on RPC server %s timed out after %s sec" % (
              func_name, self.rpcserver_host_vm.ip, self.timeout))
        except Exception as error:
          DEBUG("Asynchronous execution of method %s through watchdog"
                " raised exception: %s" % (func_name, str(error)))
          # In order to account for higher time required for
          # RPC server rehosting, the below part is handled here
          # instead of the __sender method for asynchronous execution.
          if attempt == retries or self.ping():
            ERROR("Maximum retry attempt exceeded or "
                  "RPC Server is accessible and no rehosting necessary.")
            DEBUG("Signal the ThreadPool executor (rpc exception) that it"
                  " should free any resources that it is using.")
            executor.shutdown()
            raise error
          else:
            DEBUG("Rehosting RPC Server.")
            self.rehost()
            attempt += 1
            INFO("Reattempting execution of method %s. Attempt: %d" %
                 (func_name, attempt))
    else:
      return method(self, func_name, *local_args, **kwargs)
  return method_call

class _RPCMethod:
  """Class for abstracting call to rpc server."""
  def __init__(self, sender, func_name):
    """Constructor

    Args:
      sender (func): Sender function that will be used to detect any rpc errors.
      func_name (str): Name of rpc function to call.
    """
    self.__sender = sender
    self.__func_name = func_name

  def __getattr__(self, name):
    """Allow calling nested methods.
    EX: ZeusConfigPrinter.get_zeus_config() instead of just get_zeus_config()

    Args:
      name (str): Name of attribute.

    Returns:
      attribute.
    """
    return _RPCMethod(self.__sender, "%s.%s" % (self.__func_name, name))

  def __call__(self, *args, **kwargs):
    """Allow us to wrap rpc call with error detections.
    self.__sender will be the wrapper function

    Args:
      *args (list): Args to pass to function
      **kwargs (dict): Kwargs to pass to function

    Returns:
      RPC Result.
    """
    return self.__sender(self.__func_name, args, kwargs)


class _RPCClient:
  """This class provides interface to execute RPC calls/utilities on the CVM.
  Below are the steps that are followed:
  1) XML RPC server rpc_server.py is copied on the desired CVM.
  2) XML RPC Server is run on the CVM on the desired port. Running this server
     exposes all the functions available in the util classes which can be
     accessed through the XML RPC Proxy.
  3) All the exposed RPC functions can be accesses through the XML RPC client.

  Sample Usage:
    rpc = RPCClient(cluster_obj, 8000)
    rpc.register_class_functions(
        [("/home/nutanix/zeus_printer_new.py", {"ZeusConfigPrinter": 0}),
        ("/home/nutanix/insightsdb_interface.py", {"InsightsDbInterface":
                                                  {"ip":"10.5.21.115"}})])
    rpc.ZeusConfigPrinter.get_zeus_config()
  """

  def __init__(self, entity, port,
               synch=False, timeout=600):
    """Init method of RPCClient.

    Args:
      entity (object) : The cluster, vm, or ip upon which the tests will run.
      port (int) : Port on which server will listen on.
      synch (bool): If False, RPC methods will be executed asynchronously
                    using a watchdog. If True, RPC methods will be executed
                    synchronously as they used to execute. Default is False.
      timeout (int): Timeout applicable to all XML RPC request calls.

    Returns:
      None

    Raises:
      NuTestRPCError: If the setup and/or connection fails.
    """
    self._proxy_client = None
    self.port = port
    self.synch = synch
    self.timeout = timeout
    self.__registered_class_functions = []
    self.__transfer_files = [DEFAULT_SOURCE_RPC_HELPER_DIR_PATH]

    # Cluster
    from framework.entities.cluster.base_cluster import BaseCluster
    if isinstance(entity, BaseCluster):
      self.cluster = entity
    # Ip address
    elif isinstance(entity, str):
      self.nos_vm = NOSVM(entity)
    # Assume any type of vm.
    else:
      self.nos_vm = entity

    for attempt in range(MAX_RETRIES):
      INFO("Attempt number: {count} of {total} to initialise RPC"
           .format(count=attempt+1, total=MAX_RETRIES))
      try:
        # Do initial setup
        self.select_rpcserver_host_vm()
        self.create_server_client()
        if self.ping():
          server_id = self.get_server_id()
          nutest_run_id = get_nutest_run_id()
          if nutest_run_id is None:
            DEBUG("NuTest Run ID not found")
            # Connect to the server and skip setup.
            return
          elif server_id is None:
            DEBUG("RPC server on %s does not have server ID"
                  % self.rpcserver_host_vm)
            # NuTest Run ID was found (which implies the context of a test run),
            # but the RPC server did not have one, so it can be inferred that it
            # was started outside of the current test run.
            # Stop the server and proceed with the setup.
            self.stop_rpc_server()
          elif server_id == nutest_run_id:
            DEBUG("Found RPC server of matching NuTest Run ID on %s"
                  % self.rpcserver_host_vm)
            # Connect to the server and skip setup.
            return
          else:
            DEBUG("ID of RPC server on %s does not match NuTest Run ID %s"
                  % (self.rpcserver_host_vm, nutest_run_id))
            # Stop the server and proceed with setup.
            self.stop_rpc_server()

        elif hasattr(self.rpcserver_host_vm, "enable_remote_networking"):
          self.rpcserver_host_vm.enable_remote_networking()
          # Attempt a server stop to handle the case of an RPC server up behind
          # the firewall, and then proceed with setup.
          self.stop_rpc_server()

        self.transfer_rpc_files()
        self.start_rpc_server()
        self.wait_for_server_to_come_up()
        return
      except NuTestRPCTimeoutError:
        try:
          self.stop_rpc_server()
        except Exception as err:
          WARN("Error stopping RPC server: {err}".format(err=err))

    raise NuTestRPCError("Could not initialise RPC")

  def __getattr__(self, name):
    """Allow remarshalling of attributes to _proxy_client

    __getattr__ is only invoked when an attribute is unable to be found, so it
    is still possible to get all attributes defined in _RPCClient.

    Args:
      name (str): Attribute name

    Returns:
      attribute
    """
    if name == "proxy_client":
      DEBUG("Found call to proxy_client. This is depricated functionality.")
      return self
    elif name.startswith('__') and name.endswith('__'):
      # To avoid dispatching magic methods through RPC
      DEBUG("calling default implementation for magic method %s" % name)
      return super(_RPCClient, self).__getattr__(  # pylint: disable=no-member
        name)
    else:
      DEBUG("calling rpc proxy implementation for %s" % name)
      return _RPCMethod(self.__sender, name)

  def __getstate__(self):
    """The state of the object in a form suitable to serialization using pickle

    Returns:
      dict: Object state as dictionary
    """
    # shallow copy is enough as we modify top level keys only
    state = self.__dict__.copy()
    state["_proxy_client"] = None
    return state

  def __setstate__(self, state):
    """This will be used by pickle upon de-serialization. The specified state
    will be stored in the newly created object.

    Args:
      state(dict): State of the original object in dict form.
    """
    self.__dict__.update(state)
    self.create_server_client()

  def ping(self):
    """Ping the RPC server to check if it is running.

    Returns:
      bool
    """
    sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sckt.settimeout(5)
    try:
      sckt.connect((self.rpcserver_host_vm.ip, self.port))
    except socket.timeout:
      DEBUG("Socket ping to RPC Server failed due to timeout")
      return False
    except socket.error as exc:
      DEBUG("Socket ping to RPC Server failed: %s"
            % errno.errorcode[exc.errno] if hasattr(exc, "errno") else exc)
      return False
    else:
      DEBUG("Pinging RPC Server using the proxy")
      return self._proxy_client.ping()
    finally:
      sckt.close()

  def select_rpcserver_host_vm(self):
    """Sets self.rpcserver_host_vm with an accessible vm.

    self.rpcserver_host_vm is used to setup rpc_server
    """
    # Check against _RPCMethod, as that is what is returned when cluster does
    # not  exist due to __getattr__.
    if not isinstance(self.cluster, _RPCMethod):
      try:
        self.rpcserver_host_vm = self.cluster.get_accessible_svm()
        INFO("%s is picked as host svm for RPC server" % self.rpcserver_host_vm)
      except NuTestError as exc:
        ERROR("Failed while getting accessible SVM: %s" % str(exc))
        raise NuTestRPCError("Could not find valid vm to host rpc server.")
    else:
      self.rpcserver_host_vm = self.nos_vm

  def rehost(self):
    """Select a new host vm and start the rpc server on it.

    If _RPCClient was initialized with only a vm, just try to restart the
    rpc server.

    Returns:
      None
    """
    # Check against _RPCMethod, as that is what is returned when nos_vm does
    # not exist due to __getattr__. In this case, we are running against a
    # cluster, and need to pick a new host
    if isinstance(self.nos_vm, _RPCMethod):
      self.select_rpcserver_host_vm()
      if hasattr(self.rpcserver_host_vm, "enable_remote_networking"):
        self.rpcserver_host_vm.enable_remote_networking()
      self.create_server_client()
    else:
      # If the host VM has been restarted, remote networking must be reenabled.
      if hasattr(self.rpcserver_host_vm, "enable_remote_networking"):
        self.rpcserver_host_vm.enable_remote_networking()

    # At this point, all that is left is to restart the server on either the
    # cluster or the nos_vm.
    self.transfer_rpc_files()
    self.start_rpc_server()
    self.wait_for_server_to_come_up()
    INFO("Functions: %s" % self.__registered_class_functions)
    self._proxy_client.register_class_functions( \
        self.__registered_class_functions)

  def test_rpc_helpers(self):
    """Test if all the rpc_helpers are importable."""
    self._proxy_client.test_all_helpers()

  def register_class_functions(self, class_functions):
    """Allows us to save functions registered to server and make for easy
    rehosting.

    This is a "dumb" saving method, and we will not check if functions are.

    Args:
      class_functions(list):
        [(module_path, {"class1" : {"init_param_name_1":init_param_value_1},
                        "class2" : {"init_param_name_2":init_param_value_2},
                        "class3" : 0 # No init_params for the class}),
         (module_path_2, {} # In this case module doesn't want any specific
    """
    # Check if rehosting is necessary before registering.
    # NOTE: Will not handle RPC Server failures during register_class_functions.
    if not self.ping():
      DEBUG("Rehosting RPC Server before registering class functions.")
      self.rehost()

    self.__registered_class_functions.extend(class_functions)
    self._proxy_client.register_class_functions(class_functions)

  def create_server_client(self):
    """Initiates the proxy client to RPC server.

    Returns:
      None
    """
    if self._proxy_client and self._proxy_client.ping():
      DEBUG("Proxy client already exists.")
      return
    ip = self.rpcserver_host_vm.ip
    self._proxy_client = Server("http://%s:%s/" % (ip, self.port))
    DEBUG("Created proxy server connecting to %s:%s" % (ip, self.port))

  def start_rpc_server(self, file_path='{path}/{file_name}'
                       .format(path=str(DEFAULT_TARGET_RPC_DIR_PATH),
                               file_name=SERVER_FILE_NAME)):
    """Starts rpc_server on self.ip and self.port.

    Args:
      file_path (str) : Path of the RPC server file which will be run on CVM.
        Default: /home/nutanix/rpc/rpc_server.py

    Returns:
      None

    Raises:
      NuTestError in case server is not started successfully on CVM.
    """
    if self.ping():
      DEBUG("RPC Server already running.")
      return

    # The NUTEST_RPC_PYTHON_PATH is used if the python version used to start
    # the RPC server needs to be changed. This is useful for a UT if you want
    # to test both python2 and python3. This could also be used to test
    # product side python upgrades without requiring AOS tarball changes.
    cmd = ["source", "/etc/profile.d/nutanix_env.sh", ";",
           os.environ.get("NUTEST_RPC_PYTHON_PATH", "/usr/bin/python"),
           str(file_path),
           "--rpc_ip=%s" % self.rpcserver_host_vm.ip,
           "--rpc_port=%s" % self.port]

    nutest_run_id = get_nutest_run_id()
    if nutest_run_id is not None:
      cmd.append("--nutest_run_id=%s" % nutest_run_id)

    cmd.extend([">%s" % RPC_SETUP_LOG,
                "2>&1"])
    cmd = " ".join(cmd)

    response = self.rpcserver_host_vm.execute(cmd, background=True)

    if ("error" in response["stderr"].lower() or
        "error" in response["stdout"].lower()):
      raise NuTestError('Failed to start RPC Server. stderr:%s, stdout:%s' %
                        (response["stderr"], response["stdout"]))

  def stop_rpc_server(self):
    """Terminates the RPC server. In case of threaded RPC server, it requires
    two shutdown signals to completely shutdown.
    """
    try:
      self._proxy_client.shutdown()
      self._proxy_client.shutdown()
    except Exception as exc:
      DEBUG("RPC Server shutdown exception: %s" % exc)
    finally:
      # The server sometimes persists even after successful "shutdown()" calls,
      # so preform a pkill to be sure.
      cmd = "pkill -9 -f rpc_server"
      self.rpcserver_host_vm.execute(cmd, shell_prefix=False,
                                     ignore_errors=True)

  def transfer_rpc_files(self, \
      source_rpc_helper_dir_path=None):
    """Transfers the required files to the CVM of the cluster.

    Args:
      source_rpc_helper_dir_path (FilePath object, optional): Denotes the path
        on the NuTest execution environment from where the RPC files must be
        transferred.

    Sample usage:
      Basic:
        rpc.transfer_rpc_files()
      Customized:
        rpc.transfer_rpc_files(
          source_rpc_dir_path=FilePath("FilePath.ROOT", "rpc"))
    """
    # Creating the directory.
    self.rpcserver_host_vm.mkdir(str(DEFAULT_TARGET_RPC_DIR_PATH))

    # Check to see if we are transferring a Non-default file
    if source_rpc_helper_dir_path is not None and \
        source_rpc_helper_dir_path not in self.__transfer_files:
      INFO("Transferring from custom path %s" % source_rpc_helper_dir_path)
      self.rpcserver_host_vm.transfer_to(str(source_rpc_helper_dir_path),
                                         str(DEFAULT_TARGET_RPC_DIR_PATH))
      self.__transfer_files.append(source_rpc_helper_dir_path)

    # Initiating rpc_server.py transfer.
    rpc_server_path = FilePath(str(DEFAULT_SOURCE_RPC_DIR_PATH),
                               SERVER_FILE_NAME)
    self.rpcserver_host_vm.transfer_to(str(rpc_server_path),
                                       str(DEFAULT_TARGET_RPC_DIR_PATH))

    # Initiating nutest_env.py transfer.
    rpc_server_path = FilePath(str(DEFAULT_SOURCE_RPC_DIR_PATH),
                               ENV_FILE_NAME)
    self.rpcserver_host_vm.transfer_to(str(rpc_server_path),
                                       str(DEFAULT_TARGET_RPC_DIR_PATH))

    # Copying all rpc_helper files defined under rpc_helper folder
    for helper_file in self.__transfer_files:
      rpc_helpers_path = helper_file
      self.rpcserver_host_vm.transfer_to(str(rpc_helpers_path),
                                         str(DEFAULT_TARGET_RPC_DIR_PATH))

    # "Moduling" the directory.
    self.rpcserver_host_vm.touch(os.path.join(str(DEFAULT_TARGET_RPC_DIR_PATH),
                                              '__init__.py'))

  def wait_for_server_to_come_up(self, timeout=60):
    """Waits for the XML RPC server to start responding. If server does not
    respond within the timeout, ServerNotReachableError is raised.

    Args:
      timeout (int, optional): Timeout, in seconds, to wait for server to
        start responding.

    Returns:
      None

    Raises:
      NuTestRPCTimeoutError: Incase server is not reachable in specified
        timeout.

    TODO : To convert it to timed execution
    """
    start_time = time.time()
    while True:
      if time.time() - start_time > timeout:
        raise NuTestRPCTimeoutError(
          "RPC server at %s is not reachable within %s sec" % (
            self.rpcserver_host_vm.ip, timeout),
          collector=RPCCollector(self.rpcserver_host_vm, self.port))
      DEBUG("Checking if the rpc server responds to ping")
      if self.ping():
        INFO("Successfully pinged the RPC Server at %s." %
             self.rpcserver_host_vm.ip)
        return

  def get_server_id(self):
    """Obtain the NuTest Run ID of the RPC server.

    Returns:
      str: If the ID exists.
      None: If not.

    Raises:
      Exception if obtaining the ID failed due to any reason other than being
        unsupported.
    """
    try:
      id_ = self.get_nutest_run_id() # This is the Remote Procedure.
    except NuTestRPCError as exc:
      if 'method "get_nutest_run_id" is not supported' in str(exc):
        id_ = None
      else:
        raise
    return id_

  @call_watchdog
  def __sender(self, func_name, args, kwargs):
    """Wraps rpc calls to _proxy_client to allow for error detection.

    Args:
      func_name (str): Name of rpc function to call
      args (list): *args to pass to function
      kwargs (dict): **kwargs to pass to function

    Returns:
      rpc result.
    """
    func = getattr(self._proxy_client, func_name)
    try:
      return func(*args, **kwargs)
    except Exception as error:
      # If we hit an exception, make sure to grab the log file. Logbay by
      # default doesn't download it.
      log_name = "/home/nutanix/data/logs/nutest_rpc_server.log"
      if self.rpcserver_host_vm.exists(log_name):
        self.rpcserver_host_vm.transfer_from(
          log_name,
          os.path.join(os.environ.get("NUTEST_LOGDIR", "/tmp"),
                       "nutest_rpc_server_{}_{}.log"
                       .format(self.rpcserver_host_vm.ip, time.time())))
      if not self.synch:
        raise error
      if self.rpcserver_host_vm.ip not in self.cluster.get_ignored_svm_ips() \
              and self.ping():
        DEBUG("RPC Server accessible. No rehosting necessary.")
        raise error
      else:
        DEBUG("Rehosting RPC Server.")
        self.rehost()
        func = getattr(self._proxy_client, func_name)
        return func(*args, **kwargs)

# pylint: disable=invalid-name
existing_clients = {}
lock = threading.RLock() # Lock to ensure we can't create two clients at once.
def RPCClient(entity, port=DEFAULT_SERVER_PORT, cache=None,
              synch=False, timeout=600):
  """Singleton to allow for the smart creation of rpc servers/clients

  This ensures that for any given entity-port combination, only one RPCClient is
  created.

  Args:
    entity (obj): Must be a NOSvm or NOSCluster
    port (int): Port the rpc server will run on.
    cache (bool): Whether to cache the RPC client based on target entity and
                  port.
    synch (bool): If False, RPC methods will be executed asynchronously
                  using a watchdog. If True, RPC methods will be executed
                  synchronously as they used to execute. Default is False.
    timeout (int): Timeout applicable to all XML RPC request calls.

  Returns:
    _RPCClient
  """
  _cache = cache if cache is not None else interface_consts.CACHE_RPC_CLIENTS
  # pylint: disable=global-variable-not-assigned
  global existing_clients
  key = str(entity) + "_" + str(port)

  with lock:
    if not _cache:
      return _RPCClient(entity, port, synch=synch, timeout=timeout)
    if key in existing_clients:
      DEBUG("Found existing rpc client with key %s." % key)
      return existing_clients[key]

    DEBUG("Creating new client with key %s." % key)
    client = _RPCClient(entity, port, synch=synch, timeout=timeout)
    existing_clients[key] = client
    return client

__all__ = ["RPCClient"]


class RPCCollector:
  """This is the log collector for this module"""

  def __init__(self, entity, port):
    """Constructor for the log collector class.

    Args:
      entity(object): NOSVM which was selected to host RPC server
      port(int): Port that was selected to start RPC server

    Returns:
      None
    """
    self.entity = entity
    self.port = port

  def collect(self):
    """Implements the collection of triage info.

    Args:
      None

    Returns:
      None
    """
    # Let's check if the port is busy
    response = self.entity.execute(
      "ls {logfile} && cat {logfile}".format(logfile=RPC_SETUP_LOG),
      ignore_errors=True)
    INFO("RPC server log: %s" % response["stdout"])
    response = self.entity.execute("sudo netstat -nap |grep ':%s '" % self.port)
    lines = response["stdout"].splitlines()
    if lines:
      import re
      match = re.search(r'(\d+)\/[^\s]+\s*$', lines[0])
      if match:
        pid = match.group(1)
        response = self.entity.execute("ps -ef | grep %s" % pid)
        INFO("Port %s is in use by process %s, process details are:\n%s" %
             (self.port, pid, response["stdout"]))
