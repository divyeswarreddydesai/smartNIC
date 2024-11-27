#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: isshwar.makudes@nutanix.com
"""This module defines base class for all types of timeout errors"""

from framework.exceptions.nutest_error import NuTestError

class NuTestTimeoutError(NuTestError):
  """Base class for timeout errors."""
