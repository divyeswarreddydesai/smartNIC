# Copyright (c) 2017 Nutanix Inc. All rights reserved
#
# Author: Mohammad Ghazanfar <mohammad.ghazanfar@nutanix.com>

"""This module defines operation level errors. """

from framework.exceptions.nutest_error import NuTestError

class NuTestOperationError(NuTestError):
  """Base class for operation errors. """

class NuTestOperationNotSupportedError(NuTestOperationError):
  """Operation being performed is not supported. """
