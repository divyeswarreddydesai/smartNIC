#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
"""This module defines test driver errors."""

from framework.exceptions.nutest_error import NuTestError

class NuTestRunnerTimeoutError(BaseException):
  """Base class for test execution timeout error."""
  def __init__(self, *args, **kwargs):
    """Initializer method.

    Kwargs:
      category(BaseErrorCategory): Category to which this exception belongs to.
    """
    self.category = kwargs.pop('category', None)
    super(NuTestRunnerTimeoutError, self).__init__(*args, **kwargs)

class NuTestInvalidTestOperationError(NuTestError):
  """Base class for Invalid test operation error."""

class NuTestResourceMismatchError(NuTestError):
  """Base class for Cluster Resource spec mismatch error."""

class NuTestDriverInternalError(NuTestError):
  """Any framework related internal errors"""

class NuTestWarningError(NuTestError):
  """Used when a test should be marked WARNING instead of ERROR or FAILED."""
