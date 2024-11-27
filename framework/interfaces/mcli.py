"""Python module for running commands on MCLI.

Copyrights (c) Nutanix Inc. 2018

Author: madhur.arora@nutanix.com
"""

from framework.interfaces.abstract_acli import AbstractACLI

class MCLI(AbstractACLI):
  """This class defines a standard way to execute MCLI commands.
  """
  PATH = '/usr/local/nutanix/bin/mcli'

  def _get_suitable_svm(self):
    """
    Returns an accessible svm to execute MCLI commands.
    Returns:
        SVM: svm object
    """
    needs_services_up = (len(self._cluster.svms) > 1)
    return self._cluster.get_accessible_svm(needs_services_up=needs_services_up)
