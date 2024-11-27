"""
Python module for running commands on Nuclei.

Copyrights (c) Nutanix Inc. 2018

Author: Aditya Bharti <aditya.bharti@nutanix.com>
"""

import json

from framework.interfaces.abstract_acli import AbstractACLI
from framework.exceptions.interface_error import NuTestCommandExecutionError

class NUCLEI(AbstractACLI):
  """This class defines a standard way to execute Nuclei commands. """

  PATH = '/usr/local/nutanix/bin/nuclei'
  JSON_FORMAT_OPTION = "-output_format json"

  def _get_suitable_svm(self):
    """
    Returns an accessible svm to execute Nuclei commands.

    Returns:
        SVM: svm object
    """
    return self._cluster.get_accessible_svm()

  def _parse_output(self, cmd, output):
    """
    Parses the output of the CLI cmd

    Args:
      cmd(str): The cmd that was executed.
      output(dict): The raw output of the cmd

    Returns:
      dict: output of the cmd

    Raises:
      NuTestCommandExecutionError: on failure
    """
    # Split each line and parse it as a json.
    # This may return multiple json documents one on each line.
    # For now only the last one is being considered.

    stdout_lines = output['stdout'].strip().split("\n")

    if not output['status']:
      valid_json_lines = []
      # sometimes one of the stdout lines in not a valid json
      # example: Delete 1 VMs? (yes/no) {"status": 0, "data": ... }
      for stdout_line in stdout_lines:
        try:
          json.loads(stdout_line)
          valid_json_lines.append(stdout_line)
        except ValueError:
          pass

      stdout_lines = list(map(json.loads, valid_json_lines))

      if stdout_lines:
        output['stdout'] = stdout_lines[-1]
      else:
        return {}

      if not output['stdout']['status']:
        return output['stdout']

      raise NuTestCommandExecutionError("NUCLEI command execution failed cmd:"
                                        "%s. Error: %s" %
                                        (cmd, output['stdout']['error']),
                                        response=output['stdout'])

    raise NuTestCommandExecutionError("NUCLEI command execution failed cmd:"
                                      "%s. Error: %s" %
                                      (cmd, output['status']),
                                      response=output)
