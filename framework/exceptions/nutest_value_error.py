"""
Copyright (c) 2021 Nutanix Inc. All rights reserved.

Author: raghavendra.basavara@nutanix.com

This module defines Value specific errors.
"""

class NuTestValueError(ValueError):
  """Class for NuTestValueError exception type."""

  def __init__(self, message='', **kwargs):
    """Initializer.

    Args:
      message(str): Exception string.

    Kwargs:
      category(ErrorCategory): Category to which exception belongs to.
    """
    self.category = kwargs.pop('category', None)
    super(NuTestValueError, self).__init__(message)
