"""Python module for running commands on CCLI.

Copyrights (c) Nutanix Inc. 2017

Author: shashank@nutanix.com
"""

from framework.interfaces.abstract_acli import AbstractACLI

class CCLI(AbstractACLI):
  """
  This class defines a standard way to execute CCLI commands.

  Note:- CCLI interface is not intended to be shipped with Acropolis. It is for
  internal testing and debugging purpose. This class would take care of copying
  CCLI binary to CVMs before executing commands.
  """
  PATH = '/usr/local/nutanix/bin/ccli'

  def _get_suitable_svm(self):
    """
    PC or Xi-Portal do not run acropolis process and so it does not makes sense
    to identify acropolis master svm as in case of Prism element.
    This method over-rides base class method.
    Returns:
      SVM: first svm object.
    """
    return self._cluster.svms[0]
