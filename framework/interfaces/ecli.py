"""Python module for running commands on ECLI.

Copyrights (c) Nutanix Inc. 2015

Author: shreyas.pandura@nutanix.com
        ashrith.sheshan@nutanix.com
"""

from framework.interfaces.abstract_acli import AbstractACLI

class ECLI(AbstractACLI):
  """This class defines a standard way to execute ECLI commands.
  """
  ERROR_CODES = []
  PATH = '/usr/local/nutanix/bin/ecli'

  def _get_suitable_svm(self):
    """Returns an accessible svm to execute ECLI commands.

    Returns:
        SVM: svm object
    """
    return self._cluster.get_accessible_svm(needs_services_up=True)
