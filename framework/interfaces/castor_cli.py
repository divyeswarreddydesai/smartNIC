"""Python module for running commands on castor_cli.

Copyrights (c) Nutanix Inc. 2024

Author: mayur.jaswal@nutanix.com
"""

from framework.interfaces.abstract_acli import AbstractACLI

class CastorCLI(AbstractACLI):
  """This class defines a standard way to execute castor_cli commands.
  """
  ERROR_CODES = ['InvalidArgument']
  PATH = '/usr/local/nutanix/bin/castor_cli'

  def __init__(self, opts=None, **kwargs):
    """Initializer.

    Args:
      opts ([str, (str,)]): Castor CLI options.
        Example: [("-N", "false")]
        Note: The "-o" option will be ignored since its handling is hardcoded.
    """
    super(CastorCLI, self).__init__(**kwargs)
    self.opts = [] if opts is None else opts

  def _get_cmd(self, entity, cli_cmd, **kwargs):
    """Constructs the castor_cli command by adding the correct formatting for
    entity operation and arguments.

    Args:
      entity (str): Name of the entity used in the command.
      cli_cmd (str): The operation string used in the command.
      **kwargs: Keyword arguments for the command.

    Returns:
      str: The constructed command.
    """
    cmd = super(CastorCLI, self)._get_cmd(entity, cli_cmd, **kwargs)

    opts = []
    for opt in self.opts:
      # Ignore "-o" since its handling is hardcoded in the superclass.
      if isinstance(opt, tuple) and opt[0] != "-o":
        opts.extend(opt)
      elif opt != "-o":
        opts.append(opt)

    opts_str = " ".join(opts)
    if opts_str:
      opts_str += " "

    # Insert the options just before the entity string in the command, for
    # example,
    # Before: source /etc/profile; castor_cli -o json vg.list
    # After: source /etc/profile; castor_cli -o json -n false -i vg.list
    index = cmd.index(entity + ".")
    cmd = "".join((cmd[:index], opts_str, cmd[index:]))
    return cmd

  def _get_suitable_svm(self):
    """Returns the object of an SVM that is accessible to execute the cmd.

    Returns:
        SVM: svm object
    """
    return self._cluster.get_accessible_svm()
