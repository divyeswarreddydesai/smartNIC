"""Python module for running commands on ECLI.

Copyrights (c) Nutanix Inc. 2015

Author: shreyas.pandura@nutanix.com
"""

from framework.interfaces.abstract_acli import AbstractACLI

class ACLI(AbstractACLI):
  """This class defines a standard way to execute ECLI commands.
  """
  PATH = '/usr/local/nutanix/bin/acli'

  def __init__(self, opts=None, **kwargs):
    """Initializer.

    Args:
      opts ([str, (str,)]): ACLI options.
        Example: ["-y", ("-N", "false"), "-i"]
        Note: The "-o" option will be ignored since its handling is hardcoded.
    """
    super(ACLI, self).__init__(**kwargs)
    self.opts = [] if opts is None else opts

  def _get_cmd(self, entity, cli_cmd, **kwargs):
    """Constructs the ACLI command by adding the correct formatting for entity
    operation and arguments.

    Args:
      entity (str): Name of the entity used in the command.
      cli_cmd (str): The operation string used in the command.
      **kwargs: Keyword arguments for the command.

    Returns:
      str: The constructed command.
    """
    cmd = super(ACLI, self)._get_cmd(entity, cli_cmd, **kwargs)

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
    # Before: source /etc/profile; acli -o json vm.list
    # After: source /etc/profile; acli -o json -y -N false -i vm.list
    index = cmd.index(entity + ".")
    cmd = "".join((cmd[:index], opts_str, cmd[index:]))

    return cmd
