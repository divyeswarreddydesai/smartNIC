"""Python module for running commands on Cli like ACLI, ECLI.

Copyrights (c) Nutanix Inc. 2015

Author: shreyas.pandura@nutanix.com
        ashrith.sheshan@nutanix.com
"""
# pylint: disable=arguments-differ,no-else-raise

import json
from framework.interfaces.base_cli import BaseCLI
from framework.logging.log import ERROR
from framework.logging.log import INFO

class AbstractACLI(BaseCLI):
  """This class defines a standard way to execute ACLI like commands.
  """

  ERROR_CODES = ['NoHostResources',
                 'InvalidArgument',
                 'VNumaPinningFailure']
  JSON_FORMAT_OPTION = "-o json"

  def _get_cmd(self, entity, cli_cmd, **kwargs):
    """Forms the ACLI specific cmd by adding the correct formatting for entity
    operation and arguments
    Args:
        entity (str): Name of the entity used in the cmd.
        cli_cmd (str): The operation string used in the cmd.
        **kwargs: kwargs for the cli cmd

    Returns:
      str: the cmd string
    """
    confirmation_string = kwargs.pop('confirmation_string', None)

    cmd = "{entity}.{operation} {args}".format(entity=entity,
                                               operation=cli_cmd,
                                               args=self.__generate_arg_string(
                                                 **kwargs))

    prefix = "source /etc/profile; "
    if prefix in cmd:
      prefix = ""
    if confirmation_string:
      prefix = prefix + "yes \"%s\" | " % confirmation_string

    prefix = prefix + "%s %s" % (self.PATH, self.JSON_FORMAT_OPTION)
    return "%s %s" % (prefix, cmd)

  def _get_suitable_svm(self):
    """Determines the acropolis leader svm to execute the cmd.

    Returns:
        SVM: svm object
    """
    return self._cluster.acropolis_master

  def _parse_output(self, cmd, output):
    """Parses the output of the CLI cmd
    Args:
      cmd(str): The cmd that was executed.
      output(dict): The raw output of the cmd

    Returns:
      dict: output of the cmd

    Raises:
      BaseCLIRetriesFailedError: on failure
    """
    if not output['status'] and not output['stdout']:
      INFO("Command successful, but no output returned.")
      return {'status': 0}

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
      # sometimes stdout will contain a line with no data at the end
      valid_stdout_lines = [line for line in stdout_lines
                            if 'data' in line and line['data']]


      for stdout in stdout_lines:
        if ("error" in stdout.keys() and "status" in stdout.keys()
            and stdout["error"] and stdout["status"]):
          raise ERROR("Operation failed cmd: %s "
                                            "Error: %s" %
                                            (cmd, stdout),
                                            response=stdout)

      if valid_stdout_lines:
        output['stdout'] = valid_stdout_lines[-1]
      elif stdout_lines:
        output['stdout'] = stdout_lines[-1]
      else:
        return {}

      if not output['stdout']['status']:
        error_code = [error_str for error_str in self.ERROR_CODES \
          if error_str in str(output['stdout']['data']) or \
              error_str in str(output['stdout']['error'])]
        if error_code:
          raise ERROR("Operation failed cmd: %s "
                                            "Error: %s" %
                                            (cmd, output['stdout']),
                                            response=output['stdout'])
        else:
          return output['stdout']

      raise ERROR("ACLI command execution failed cmd: %s"
                                        "Error: %s" %
                                        (cmd, output['stdout']['error']),
                                        response=output['stdout'])

    raise ERROR("ACLI command execution failed "
                                      "cmd: %s. Error: %s" %
                                      (cmd, output['status']),
                                      response=output)

  @staticmethod
  def __generate_arg_string(**kwargs):
    """This routine generates arguments for a acli command.

    kwargs:
      kwargs: List of parameters executed during the test run.

    Returns:
      str: A string which contains the CLI parameters and their values in this
           fashion "key1=value1 key2=value2...".
    """

    str_list = []
    no_key_args = kwargs.pop("no_key", [])
    for arg in no_key_args:
      str_list.append(str(arg))

    for key in kwargs:
      cmd_string = "%s=\"%s\"" % (key, kwargs[key])
      str_list.append(cmd_string)

    return str(" ".join(str_list))
