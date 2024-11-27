#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: anirudh.sonar@nutanix.com
"""This module define hypervisor manager errors."""

from framework.exceptions.nutest_error import NuTestError

class HypervisorManagerOperationError(NuTestError):
  """Hypervisor manager Operation Error"""

class HypervisorManagerTimeoutError(HypervisorManagerOperationError):
  """Hypervisor manager timeout  Error"""
