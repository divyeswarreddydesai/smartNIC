"""Python module for running commands on NCLI.

Copyrights (c) Nutanix Inc. 2015

Authors: shreyas.pandura@nutanix.com,
         ashrith.sheshan@nutanix.com
"""

import json
import re
import time

from framework.exceptions.interface_error import NuTestCommandExecutionError
from framework.exceptions.interface_error import NuTestPrismDownError
from framework.interfaces.base_cli import BaseCLI
from framework.lib.error_categorisation import ErrorCategory
from framework.lib.nulog import WARN, ERROR, INFO

# pylint: disable=invalid-sequence-index, arguments-differ

class NCLI(BaseCLI):
  """This class defines a standard way to execute NCLI commands.
  """
  PATH = '/home/nutanix/prism/cli/ncli'
  PRISM_GATEWAY_DOWN = "Error: Could not connect to Nutanix Gateway"
  ERROR_CODES = []

  def is_up(self):
    """
    Checks if the instance of ncli is backed by a working service.

    Returns:
      bool: True if the service is up, False otherwise.
    """
    try:
      self.execute("cluster", "status")
      INFO("NCLI is up.")
      return True
    except NuTestCommandExecutionError:
      INFO("NCLI seems to be down.")
      return False

  def _execute(self, svm, ncli_cmd, retries=3, retry_interval=60,
               log_response=True, **kwargs):
    """This  method is used to execute a NCLI command on an SVM.
    1. Execute the cmd via ssh on the svm
    2. Try to parse the result of the CLI cmd and return output
    Args:
      svm(SVM): SVM object on which the cmd is executed.
      ncli_cmd(str): NCLI command to be executed.
      retries(int, optional): Number of retries. Default: 3.
      retry_interval(int): Time in secs to wait between retries. Default 60.
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False.
      **kwargs:
        timeout(int): Timeout in secs for the cmd execution to complete.
          Default: 60.

    Returns:
       dict: Dictionary with status and output.

    Raises:
      NuTestPrismDownError: When failed to execute command due to prism
                            gateway being down.
    """
    result = {}

    # 1. Execute the cmd via ssh on the SVM
    attempts = 0
    exc = None
    while attempts < retries:
      try:
        result = svm.execute(ncli_cmd, log_response=log_response, **kwargs)
        break
      except NuTestCommandExecutionError as exception:
        exc = exception
        # We should retry in sometime if prism gateway is down.
        if re.search(NCLI.PRISM_GATEWAY_DOWN, str(exc)):
          WARN("Nutanix/Prism gateway is down. Sleeping for %s "
               "seconds before retry... " % retry_interval)
          if hasattr(self, "_cluster"):
            svm = self._get_accessible_svm()
            INFO("Retrying command %s on SVM %s" % (ncli_cmd, svm.ip))
          time.sleep(retry_interval)
          attempts += 1
        else:
          ERROR("cmd on %s failed: %s" % (svm.ip, ncli_cmd))
          raise
    else:
      ERROR("cmd on %s failed: %s" % (svm.ip, ncli_cmd))
      if re.search(NCLI.PRISM_GATEWAY_DOWN, str(exc)):
        raise NuTestPrismDownError("Prism gateway is down",
                                   category=ErrorCategory.RESOURCE_STATE)

    # 2. Try to parse the result and return the output
    return self._parse_output(ncli_cmd, result)

  def _get_cmd(self, entity, cli_cmd, **kwargs):
    """Forms the CLI specific cmd by adding the correct formatting for entity
    operation and arguments
    Args:
        entity (str): Name of the entity used in the cmd.
        cli_cmd (str): The operation string used in the cmd.
        **kwargs: kwargs for the cli cmd

    Returns:
      str: the cmd string
    """
    cmd = "{entity} {operation} {args}".format(entity=entity,
                                               operation=cli_cmd,
                                               args=self.__generate_arg_string(
                                                 **kwargs))
    prefix = 'source /etc/profile;'
    if prefix in cli_cmd:
      prefix = "%s -json=true" % (NCLI.PATH)
    else:
      prefix = "%s %s -json=true" % (prefix, NCLI.PATH)
    return "%s %s" % (prefix, cmd)

  def _get_suitable_svm(self):
    """Determines the prism leader svm to execute the cmd.

    Returns:
        SVM: svm object
    """
    return self._cluster.prism_leader

  def _parse_output(self, cmd, output):
    """Parses the output of the CLI co
    Args:
      cmd(str): The cmd that was executed.
      output(str): The raw output of the cmd

    Returns:
      dict: output of the cmd

    Raises:
      NuTestCommandExecutionError
    """
    try:
      # For some NCLI commands, like 'ncli software upload',
      # there may be 2 jsons returned. We only care about the last json.
      output_lines = output['stdout'].splitlines()
      output['stdout'] = json.loads(output_lines[-1])
    except ValueError:
      raise NuTestCommandExecutionError("NCLI command execution failed: "
                                        "cmd: %s Error: %s" %
                                        (cmd, output['stdout']),
                                        response=output_lines[-1])
    if not output['status'] and not output['stdout']['status']:
      return output['stdout']
    if output["stdout"]["status"]:
      expt = NuTestCommandExecutionError(output["stdout"]["data"])
      expt.command = cmd
      expt.response = output["stdout"]
      raise expt
    raise NuTestCommandExecutionError("NCLI command execution failed: "
                                      "cmd: %s Error: %s" %
                                      (cmd, output['stdout']['data']),
                                      response=output['stdout'])

  @staticmethod
  def __generate_arg_string(**kwargs):
    """This routine generates arguments for a ncli command.

    kwargs:
      kwargs: List of parameters executed during the test run.

    Returns:
      A string which contains NCLI parameters and their values in this
      fashion "key1=value1 key2=value2...".
    """
    str_list = []

    for key, value in kwargs.items():

      # We have a boolean value, we should not put it in quotes.
      if isinstance(value, bool):
        value = "true" if value else "false"
      else:
        value = "\"%s\"" % value
      # Convert all underscores to hyphen (if any).
      if '_' in key:
        key = key.replace('_', '-')

      cmd_string = "%s=%s" % (key, value)
      str_list.append(cmd_string)
    return " ".join(str_list)
