#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: asonar@nutanix.com
"""This module defines hypervisor related errors."""

from framework.exceptions.nutest_error import NuTestError

#pylint: disable=redefined-builtin
class ConnectionError(NuTestError):
  """Base class for connection errors"""
#pylint: enable=redefined-builtin

class InvalidStateError(NuTestError):
  """Invalid state error for the hypervisor/resource. """
