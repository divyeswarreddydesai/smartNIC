"""
Copyright (c) 2016 Nutanix Inc. All rights reserved.

Author: daniel.shubin@nutanix.com

Impliment progress monitor cli
"""
# pylint: disable=no-self-use,anomalous-backslash-in-string
# pylint: disable=arguments-differ,no-else-return,no-else-continue
import re
import time

from framework.components.genesis import Genesis
from framework.exceptions.interface_error import NuTestCommandExecutionError, \
    NuTestSSHError
from framework.exceptions.nutest_error import NuTestError
from framework.interfaces.base_cli import BaseCLI

from framework.lib.error_categorisation import ErrorCategory
from framework.lib.nulog import DEBUG, INFO


class ProgressMonitorCLI(BaseCLI):
  """
  Abstraction for progress monitor cli
  """
  PATH = "/usr/local/nutanix/bin/progress_monitor_cli"
  NO_OBJECT_ERROR = "Lookup failed with error kNoObject"

  def execute(self, cmd, retries=None, timeout=60, log_response=True,
              **kwargs):
    """This method executes a CLI command.

    Overwriting because progress_monitor_cli does not make use of entities as
    BaseCLI expects.

    1. Forms the cmd to run
    2. Determines the prism leader in case of cluster/ Finds the SVM to run
    3. Get the execution params from test config and override if not implicitly
       passed in the function call.
    4. Try to execute the CMD on the svm found with retries.

    Args:
      cmd(str): The cmd that will be executed.
      retries(int, optional): The number of retries to be attempted for command
                            execution.
                            Default: Taken from global test settings.
      timeout(int, optional): Timeout in seconds for the command to be executed.
                              Default: 60 secs
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False.
      kwargs(dict): The key-value pairs that will be used in cli command.

    Returns:
      This routine returns a dictionary with 'status' and 'stdout' of the
      CLI command executed.

    Raises:
      NuTestCommandExecutionError: If cmd execution fails.
    """
    # 1. Forms the cmd from the cli cmd format.
    cmd = self._get_cmd(cmd, **kwargs)

    # 2. Determines the prism leader in case of cluster/ Finds the SVM to run
    if hasattr(self, '_cluster'):
      svm = self._get_suitable_svm()
    else:
      svm = self._svm

    # 3. Get the execution params from test config and override if not
    # implicitly passed in the function call.
    if not retries:
      retries = 3

    # config_retries defines the number of time a CLI command will be retried
    # in case it throws NuTestCommandExecutionError.
    config_retries = self._config.pop('interface_retries', 1)

    # retry_interval defines the sleep duration in seconds between retries.
    retry_interval = self._config.pop('interface_retry_interval', 10)

    # 4. Try to execute the CMD on the svm found with retries.
    attempts = 0
    while attempts <= config_retries:
      attempts += 1
      try:
        return self._execute(svm, cmd, log_response=log_response,
                             timeout=timeout)
      except NuTestCommandExecutionError as exc:
        exception = exc
        time.sleep(retry_interval)

        # Get new svm on each retry, as a possible failure reason is the svm
        # went down. This would be expected as most progress monitors are used
        # to track upgrades, which have rolling restarts.
        if hasattr(self, '_cluster'):
          svm = self._get_suitable_svm()
      # Sometimes ssh doesn't open a channel AND does not retry. We have to
      # handle the retry on our own until AUTO-12278 is fixed
      except NuTestSSHError as exc:
        exception = exc
    raise exception

  def _get_cmd(self, cli_cmd, **kwargs):
    """Format progress monitor string.

    Args:
      cli_cmd(str): one of fetchall or delete.
      kwargs:
        operation(str): operation type
        entity_type(str): type of entity
        entity_id(str): entity id

    Returns:
      str: command to run progress monitor cli.
    """
    prefix = "source /etc/profile; %s " % self.PATH

    if not cli_cmd.startswith("--"):
      cli_cmd = "--%s" % cli_cmd

    extra_cmd = ""
    for key, value in list(kwargs.items()):
      extra_cmd = extra_cmd + " --%s=%s" % (key, value)

    cmd = cli_cmd + extra_cmd
    return prefix + cmd

  def _get_suitable_svm(self):
    """Determine an svm that is up and running.

    Returns:
        SVM: svm object

    Raises:
      NuTestCommandExecutionError: no svms available
    """
    required_services = ["genesis", "zookeeper", "cassandra", "stargate"]
    svms = self._cluster.svms
    for svm in svms:
      genesis = Genesis(svm)

      try:
        status = genesis.status()
      except NuTestError:
        DEBUG("Could not run genesis status on %s" % svm.ip)
        continue # SVM is down.

      for service in required_services:
        # Check for any number of digits, commas, or spaces
        match = re.search("%s: (\[[0-9, ]*\])" % service, \
            status[svm.ip]["stdout"])
        if not match or match.group(1) == "[]":
          INFO("Service %s is not up on %s" % (service, svm.ip))
          break
      else:
        return svm
    raise NuTestCommandExecutionError("No available svms",
                                      category=ErrorCategory.RESOURCE_STATE)

  def _parse_output(self, cmd, result):
    """To be implemented by the subclass. Parses the output of the CLI cmd.

    There are 3 possible commands for progress monitor cli:
      fetchall
      delete
      lookup

    Each command has different output form.

    This parse_output will determine which command was run and pass the output
    to the corresponding _<cmd>_parse_output.

    Args:
      cmd (str): cmd executed.
      result (dict): Raw output of the CLI cmd.

    Returns:
      dict: output of the cli cmd

    Raises:
      NuTestCommandExecutionError: on failure
    """
    if "fetchall" in cmd:
      return self._fetchall_parse_output(result)
    elif "lookup" in cmd:
      return self._lookup_parse_output(result)
    elif "delete" in cmd:
      return self._delete_parse_output(result)
    else:
      raise NuTestCommandExecutionError(
        "Unknown command: %s" % cmd, category=ErrorCategory.INVALID_OPERATION)

  def _fetchall_parse_output(self, result):
    """Parse fetchall output

    Progress monitor output parsing is interesting. The stdout of a cli command
    is going to be a "list" of protos, where each proto is contained in
      "======================== Proto Start ============================="
    and
      "======================== Proto End ==============================="

    each proto has entries of key value pairs in two forms:
      1. key: value - value is a single entry
      2. key1 {
          key2: value
          ...
        }
      key1 in option 2 does not have to be unique, in which case each time
        key1 appears in a proto, it is another entry in a list.
      value for key2 can be another option 2 entry.

    To parse this, we first start be seperating the protos.
    We then scan through each proto and create a stack.
    Each line will initially get its own entry into the stack.
      If we have option 1 entry, the line is converted directly to a dict and
        inserted into the stack.
      If we find an option 2 (denoted by an open bracket '{'), we just append
        the entire line and continue to the next.
        once we find the matching '}', we reverse through the stack, poping
        each entry and create a sub dict of all the entries between the two
        matching brackets. We then add an entry to the stack of
        key: sub_dict where key is from key1 { in entry option 2.
    Last, we convert the entire stack into a dict_ using the above idea. We will
      also have to watch for multiple of the same key, and then instead of
      key: dict_, we have key: [dict_1, dict_2...]

    Args:
      result (dict): Raw output of the CLI cmd.

    Returns:
      list of dicts: output of the cli cmd
    """
    json_protos = []
    dict_processing_marker = False
    # Each proto in protos will start with "Proto Start" Line.
    protos = result["stdout"].split("Proto Start")
    for proto in protos:
      if not proto or 'progress_info_id' not in proto:
        continue
      proto_stack, stack = [], []
      for line in proto.splitlines():
        if "====" in line:
          continue
        if ':' in line:
          if dict_processing_marker:
            stack.append(self.__string_to_dict(line))
          else:
            proto_stack.append(self.__string_to_dict(line))
        elif '{' in line:
          dict_processing_marker = True
          proto_stack.append(self.__stack_to_dict(stack))
          stack = []
          stack.append(line)
        elif '}' in line:
          dict_processing_marker = False
          proto_stack.append(self.__stack_to_dict(stack))
          stack = []
      if proto_stack:  # Only do if we have a stack. Otherwise we get {}
        json_protos.append(self.__stack_to_dict(proto_stack))

    DEBUG("Progress monitor dict from fetchall command:\n%s" % json_protos)
    return json_protos

  def _lookup_parse_output(self, result):
    """Parse lookup output

    Progress monitor output parsing is interesting. The stdout of a cli command
    is going to be a single proto that has entries of key value pairs
    in two forms:
      1. key: value - value is a single entry
      2. key1 {
          key2: value
          ...
        }
      key1 in option 2 does not have to be unique, in which case each time
        key1 appears in a proto, it is another entry in a list.
      value for key2 can be another option 2 entry.

    To parse this, we first start be seperating the protos.
    We then scan through each proto and create a stack.
    Each line will initially get its own entry into the stack.
      If we have option 1 entry, the line is converted directly to a dict and
        inserted into the stack.
      If we find an option 2 (denoted by an open bracket '{'), we just append
        the entire line and continue to the next.
        once we find the matching '}', we reverse through the stack, poping
        each entry and create a sub dict of all the entries between the two
        matching brackets. We then add an entry to the stack of
        key: sub_dict where key is from key1 { in entry option 2.
    Last, we convert the entire stack into a dict_ using the above idea. We will
      also have to watch for multiple of the same key, and then instead of
      key: dict_, we have key: [dict_1, dict_2...]

    Args:
      result (dict): Raw output of the CLI cmd.

    Returns:
      dict: json formatted progress monitor
    """
    proto = result["stdout"]
    dict_processing_marker = False
    proto_stack, stack = [], []
    for line in proto.splitlines():
      if ':' in line:
        if dict_processing_marker:
          stack.append(self.__string_to_dict(line))
        else:
          proto_stack.append(self.__string_to_dict(line))
      elif '{' in line:
        dict_processing_marker = True
        proto_stack.append(self.__stack_to_dict(stack))
        stack = []
        stack.append(line)
      elif '}' in line:
        dict_processing_marker = False
        proto_stack.append(self.__stack_to_dict(stack))
        stack = []
    if proto_stack: # Only do if we have a stack. Otherwise we get {}
      json_proto = self.__stack_to_dict(proto_stack)
      DEBUG("Progress monitor dict from lookup command:\n%s" % json_proto)
      return json_proto
    else:
      DEBUG("Progress monitor dict from lookup command:\n{}")
      return {}

  def _delete_parse_output(self, result):
    """Parse delete output.

    The output for a delete command is much simpler, usually just a string.

    Args:
      result (dict): Raw output of CLI cmd.

    Returns:
      dict: output of cli cmd
    """
    return {"output": result["stdout"]}

  def __string_to_dict(self, string):
    """Parse a string into a dict.

    String must be of form:
      key: value OR key:

    "key:" option means a key with no value

    Args:
      string(str): a string of above form.

    Returns:
      dict: {key: value} from string
    """
    # Split the string on first occurrence of ":" since the value may contain
    # colons too.
    split = string.split(':', 1)
    if len(split) == 1:
      split.append("")
    return {split[0].strip(): split[1].strip().replace('"', '')}

  def __stack_to_dict(self, stack):
    """Convert a stack to a dict.

    Each entry in stack is a single dict entry.

    Args:
      stack(list): a list of dict entries - can be emtpy

    Returns:
      dict
    """
    dict_ = {}
    while len(stack) != 0:
      item = stack.pop()
      if not item:
        continue
      elif "{" in item: # At the start of a dict.
        return {item.split()[0]: dict_}
      elif isinstance(item, dict):
        key = list(item.keys())[0]
        value = item[key]
        if key in dict_:
          if isinstance(dict_[key], list):
            dict_[key].append(value)
          else:
            dict_[key] = [dict_[key], value]
        else:
          if "list" in key:
            dict_[key] = [value]
          else:
            dict_[key] = value
      else:
        raise NuTestCommandExecutionError("Unable to parse stack %s" % item)
    return dict_
