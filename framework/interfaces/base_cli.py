"""Python module for running commands on CLIs similar to NCLI, ACLI, ECLI etc.

Copyrights (c) Nutanix Inc. 2016

Author: shreyas.pandura@nutanix.com,
        ashrith.sheshan@nutanix.com
"""
# pylint: disable=invalid-sequence-index, too-many-locals
# pylint: disable=raising-bad-type, import-outside-toplevel
# pylint: disable=unused-import
# pylint: disable=invalid-name

import json
import os
import sys
import time
from abc import abstractmethod

from framework.entities.vm.pcvm import PCVM
from framework.lib.error_categorisation import ErrorCategory
from framework.lib.nulog import DEBUG, ERROR, WARN, INFO
from framework.exceptions.interface_error import \
  NuTestHTTPError, NuTestCommandExecutionError, NuTestSSHConnectionError,\
  NuTestSSHConnectionTimeoutError, NuTestSSHTimeoutError
from framework.exceptions.nutest_value_error import NuTestValueError
from framework.interfaces.http.http import HTTP

class BaseCLI:
  """This class defines a standard way to execute CLI commands.
  """

  PATH = None
  ERROR_CODES = []

  def __init__(self, **kwargs):
    """Initialize instance of BaseCLI.

    Args:
      **kwargs:
        cluster(Cluster): Cluster Object.
        svm(SVM): SVM Object.

    Raises:
      NuTestValueError: when either cluster or svm is not provided
    """
    from framework.entities.cluster.base_cluster import BaseCluster
    from framework.entities.vm.nos_vm import NOSVM
    from framework.operating_systems.operating_system.linux_operating_system \
      import LinuxOperatingSystem
    if kwargs.get('cluster'):
      cluster = kwargs.get('cluster')
      if isinstance(cluster, BaseCluster):
        self._cluster = cluster
      elif isinstance(cluster, PCVM):
        self._svm = cluster
      else:
        raise NuTestValueError("Cluster object Expected. Passed: %s" %
                               str(cluster), category=ErrorCategory.USAGE)
    elif kwargs.get('svm'):
      svm = kwargs.get('svm')
      if not isinstance(svm, NOSVM):
        raise NuTestValueError("NOSVM object Expected. But Passed:%s"
                               % str(svm), category=ErrorCategory.USAGE)
      self._svm = svm
    elif kwargs.get('vm'):
      vm = kwargs.get('vm')
      if not isinstance(vm, LinuxOperatingSystem):
        raise NuTestValueError(
          "LinuxOperatingSystem object Expected. But passed: %s" % str(vm),
          category=ErrorCategory.USAGE)
    else:
      raise NuTestValueError("Either of SVM or Cluster objects are mandatory.",
                             category=ErrorCategory.USAGE)

    self._config = self.__get_config()

    # Default exceptions to retry on if interface retries are enabled.
    self._default_interface_retry_exceptions = \
                                              [NuTestCommandExecutionError,
                                               NuTestSSHConnectionError,
                                               NuTestSSHConnectionTimeoutError]

  def execute(self, entity, cmd, retries=None, timeout=300,
              log_response=True, session_timeout=10,
              close_ssh_connection=False, **kwargs):
    """This method executes a CLI command.
    1. Forms the cmd to run
    2. Determines the prism leader in case of cluster/ Finds the SVM to run
    3. Get the execution params from test config and override if not implicitly
       passed in the function call.
    4. Try to execute the CMD on the svm found with retries.

    Args:
      entity(str): The entity on which the cmd is run on.
      cmd(str): The cmd that will be executed.
      retries(int, optional): The number of retries to be attempted for command
                            execution.
                            Default: Taken from global test settings.
      timeout(int, optional): Timeout in seconds for the command to be executed.
                              Default: 60 secs
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.
      close_ssh_connection (bool, Optional): Flag to set whether to close the
              SSH connection used for command execution.
              False by default.
      kwargs(dict): The key-value pairs that will be used in cli command.

    Returns:
      This routine returns a dictionary with 'status' and 'stdout' of the
      CLI command executed.

    Raises:
      NuTestCommandExecutionError: If cmd execution fails.
      NuTestSSHConnectionError: If cmd execution fails due to connection error.
      NuTestSSHConnectionTimeoutError: If cmd execution fails due to ssh
        connection timeout error.
    """

    # config_retries defines the number of time a CLI command will be retried
    # in case it throws NuTestCommandExecutionError.
    config_retries = self._config.get('interface_retries', 1)

    # retrieving interface_retries in the kwargs for
    # rdm plugin to pass it as 0 to avoid retries
    interface_retries = kwargs.pop("interface_retries", None)
    if interface_retries is not None:
      config_retries = interface_retries

    # 1. Forms the cmd from the cli cmd format.
    cmd = self._get_cmd(entity, cmd, **kwargs)

    # 2. Determines the prism leader in case of cluster/ Finds the SVM to run
    if hasattr(self, '_cluster'):
      svm = self._get_accessible_svm()
    else:
      svm = self._svm

    # 3. Get the execution params from test config and override if not
    # implicitly passed in the function call.
    if not retries:
      retries = 3

    # retry_interval defines the sleep duration in seconds between retries.
    retry_interval = self._config.get('interface_retry_interval', 10)

    # interface_retry_on_exception_list defines the list of exceptions
    # to do retries on. The list is collection of exception class names
    # passed as strings. We will convert the strings to class names if
    # they have been imported rightly above. Any class passed and not
    # imported here would act like it was never passed and exception
    # will be raised when received.
    custom_exceptions = \
      self._config.get('interface_retry_on_exception_list', [])
    retry_exceptions = self._default_interface_retry_exceptions

    for custom_exception in custom_exceptions:
      try:
        exp_class = getattr(sys.modules[__name__], custom_exception)
        retry_exceptions.append(exp_class)
      except AttributeError:
        ERROR("%s not imported correctly" % custom_exception)
        continue

    # 4. Try to execute the CMD on the svm found with retries.
    attempt = 0
    while attempt <= config_retries:
      attempt += 1

      try:
        DEBUG("Executing %s, SVM: %s, Attempt: %s" % (cmd, svm, attempt))
        result = self._execute(svm, cmd, retries=retries, timeout=timeout,
                               log_response=log_response,
                               session_timeout=session_timeout,
                               close_ssh_connection=close_ssh_connection)
        return result

      # pylint: disable=broad-except
      except Exception as exception:
        # Python3 clears the above 'exception' object once its out of scope
        # as it now holds a reference within it for the exception traceback.
        # We copy the exception to another object and reset its traceback
        # pointer to allow it to be garbage collected once the except clause
        # is out of scope. The copied exception object can be referenced
        # from outer scopes.
        exc = exception
        exc.__traceback__ = None
        DEBUG("Received exception %s: %s" % (type(exception), exception))
        if isinstance(exception, tuple(retry_exceptions)):
          time.sleep(retry_interval)
          if hasattr(self, '_cluster'):
            svm = self._get_accessible_svm()
        else:
          raise

    raise exc

  def _execute(self, svm, cli_cmd, log_response=True, **kwargs):
    """This  method is used to execute a CLI command on an SVM.
    1. Execute the cmd via ssh on the svm
    2. Try to parse the result of the CLI cmd and return output
    Args:
      svm(SVM): SVM object on which the cmd is executed.
      cli_cmd(str): CLI command to be executed.
      log_response (bool, Optional): True when response is supposed to
                                     be logged, else False.
      **kwargs:
        retries(int): Number of retries.
        timeout(int): Timeout for the cmd.

    Returns:
       dict: Dictionary with status and output.

    Raises:
      NuTestCommandExecutionError: If cmd execution fails.
    """
    # 1. Execute the cmd via ssh on the SVM
    result = svm.execute(cli_cmd, log_response=log_response, **kwargs)

    # 2. Try to parse the result and return the output
    return self._parse_output(cli_cmd, result)

  @abstractmethod
  def _get_cmd(self, entity, cli_cmd, **kwargs):
    """To be implemented by the subclass.
    Forms the CLI specific cmd by adding the correct formatting for entity
    operation and arguments

    Args:
        entity (str): Name of the entity used in the cmd.
        cli_cmd (str): The operation string used in the cmd.
        **kwargs: kwargs for the cli cmd

    Returns:
      str: the cmd string

    Raises:
      None
    """
    raise NotImplementedError

  def _get_suitable_svm(self):
    """To be implemented by the subclass. Determines the svm to execute the cmd.

    Returns:
      SVM: svm object

    Raises:
      EntityOperationFailedError: on failure to get a suitable svm
    """
    raise NotImplementedError

  def _get_accessible_svm(self):
    """Returns accessible SVM of the cluster.

    Returns:
      SVM: svm object
    """
    return self._cluster.get_accessible_svm()

  def _parse_output(self, cmd, result):
    """To be implemented by the subclass. Parses the output of the CLI cmd.

    Args:
      cmd (str): cmd executed.
      result (dict): Raw output of the CLI cmd.

    Returns:
      dict: output of the cli cmd

    Raises:
      NuTestCommandExecutionError: on failure
    """
    raise NotImplementedError

  @staticmethod
  def __get_config():
    """Gets the test config for interface for getting retry, timeout and sleep
    interval settings

    Returns:
      dict: config = {
        'interface_retries': 3,
        'interface_retry_interval': 60
      }

    Raises:
      NuTestValueError: When failed to fetch config details.
    """
    config = {
      'interface_retries': 1,
      'interface_retry_interval': 10
    }
    try:
      url = os.environ.get('TEST_RESULT_URL')
      if url is None:
        return config
      http = HTTP(retries=1, timeout=60)
      response = http.get(url, debug=False)
      if not response.ok:
        raise NuTestValueError("Failed while fetching config details: %s" %
                               response, category=ErrorCategory.NUTEST_INTERNAL)
      test_data = json.loads(response.content)
      for key in config:
        if key in test_data['params']:
          config[key] = test_data['params'][key]
    except (ValueError, NuTestHTTPError):
      WARN('Unable to read test/global config for interfaces. '
           'Falling back to default.')
    return config
