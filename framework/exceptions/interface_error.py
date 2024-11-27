#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
"""This module defines interface layer errors."""

from framework.exceptions.nutest_error import NuTestError

class NuTestInterfaceError(NuTestError):
  """Base class for interface layer errors."""

class NuTestSSHError(NuTestInterfaceError):
  """Base class for SSH errors."""

class NuTestSSHConnectionError(NuTestSSHError):
  """Base class for SSH connection errors."""

class NuTestSSHAuthenticationError(NuTestSSHConnectionError):
  """Base class for SSH Authentication errors."""

class NuTestSSHChannelError(NuTestSSHError):
  """Base class for SSH connection errors."""

class NuTestSSHTimeoutError(NuTestSSHError):
  """Base class for SSH timeout errors."""

class NuTestSSHConnectionTimeoutError(NuTestSSHTimeoutError):
  """Base class for SSH connection timeout errors."""

class NuTestInterfaceTransportError(NuTestInterfaceError):
  """
  Class for transport level failures of interfaces interaction.
  """

class NuTestHTTPError(NuTestInterfaceError):
  """Base class for HTTP errors."""

  def __init__(self, *args, **kwargs):
    """Constructor for HTTP Error"""
    self.response = kwargs.pop('response', None)
    super(NuTestHTTPError, self).__init__(*args, **kwargs)

class NuTestPrismError(NuTestHTTPError):
  """Class for Prism errors."""

class NuTestClientAuthenticationError(NuTestPrismError):
  """Class for Client Authentication errors. """

class NuTestClientForbiddenError(NuTestPrismError):
  """Class for Client Forbidden errors. """

class NuTestPrismDownError(NuTestPrismError):
  """Class for Prism down errors."""

class NutestPrismEditConflictError(NuTestPrismError):
  """Class for Prism PUT(Edit) Conflict errors."""

class NuTestHTTPTimeoutError(NuTestHTTPError):
  """Base class for HTTP timeout errors."""

class NuTestWSMANError(NuTestInterfaceError):
  """Base class for WSMAN errors."""

class NuTestWSMANTimeoutError(NuTestWSMANError):
  """Base class for WSMAN timeout errors."""

class NuTestWSMANAuthenticationError(NuTestWSMANError):
  """Class for WSMAN Authentication errors."""

class NuTestRPCError(NuTestError):
  """Base class for RPC errors."""

class NuTestRPCTimeoutError(NuTestRPCError):
  """Base class for RPC timeout errors."""

class NuTestCommandExecutionError(NuTestError):
  """Base class for OS, NCLI, ACLI, ECLI, PRISM REST, Cluster commands
  execution errors."""

class NuTestCommandTimeoutError(NuTestError):
  """Base class for OS, NCLI, ACLI, ECLI, PRISM REST, Cluster commands
  execution timeout errors."""

class NuTestImagingError(NuTestError):
  """Base class for all Task timeout related errors."""

class NuTestNxctlError(NuTestHTTPError):
  """Class for Nxctl errors."""

class NuTestNxctlAuthenticationError(NuTestNxctlError):
  """Class for Client Authentication errors. """
