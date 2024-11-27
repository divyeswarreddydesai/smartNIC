#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
"""This module defines entity layer errors."""

from framework.exceptions.nutest_error import NuTestError

class NuTestEntityError(NuTestError):
  """Base class for entity layer errors."""

  def __init__(self, message='', response=None, **kwargs):
    """
    Initializer for NuTestEntityError exception.

    Args:
      message(str): Exception message.
      response(dict): HTTP Response dict.
    """
    super(NuTestEntityError, self).__init__(message=message, **kwargs)
    self.response = response

class NuTestEntityMissingError(NuTestEntityError):
  """Entity missing error."""

class NuTestEntityOperationError(NuTestEntityError):
  """Entity CRUD error."""

class NuTestEntityOperationTimeoutError(NuTestEntityError):
  """Entity Operation Timeout Error"""

class NuTestEntityValidationError(NuTestEntityError):
  """Entity Validation error."""

class AnotherTaskInProgressError(NuTestEntityError):
  """Another Task in progress error."""

class NuTestEntityDeletionInProgressError(NuTestEntityError):
  """Entity under deletion status error."""
