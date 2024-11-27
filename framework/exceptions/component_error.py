#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
"""This module defines component or service layer errors."""

from framework.exceptions.nutest_error import NuTestError

class NuTestComponentError(NuTestError):
  """Base class for NOS component layer errors."""

class NuTestComponentExecutionError(NuTestComponentError):
  """ Generic class for all NuTest Component execution errors. """

  def __init__(self, message='', collector=None, **kwargs):
    """
    Constructor for NuTestComponentExecutionError.

    Args:
      message (string): Refer NuTestError.
      collector (object): Refer NuTestError.
      ... (...): Refer NuTestError.

    Kwargs:
      err_code (int): Error code of the Cerebro Call.
      err_msg (string): Error message of the Cerebro call.
    """

    self.err_code = kwargs.pop('err_code', -1)
    self.err_msg = kwargs.pop('err_msg', None)

    super(NuTestComponentExecutionError, self).__init__(
      message, collector, **kwargs)
