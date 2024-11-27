"""This file implements a convenience class for interface types via which the
system under test will be accessed.

Copyright (c) 2016 Nutanix Inc. All rights reserved.

Author: bgangadharan@nutanix.com
"""
import re
from framework.lib.error_categorisation import ErrorCategory
from framework.exceptions.nutest_value_error import NuTestValueError

class Interface:
  """This class is an enum of interface types for the system under test.
  """
  NCLI = "NCLI"
  ACLI = "ACLI"
  ECLI = "ECLI"
  CCLI = "CCLI"
  REST = "REST"
  RPC = "RPC"
  NATIVE = "NATIVE"
  NUCLEI = "NUCLEI"
  SDK = "SDK"
  CASTOR_CLI = "CASTOR_CLI"

  # Product Specific Interfaces
  AOS = "AOS"
  LTSS = "LTSS"

  # Object Store Specific Interfaces
  S3Boto3 = "S3Boto3"
  S3CLI = "S3CLI"

  # NUCAS Specific Interfaces
  EKS_CLI = "EKS_CLI"
  EKS_API = "EKS_API"
  NXCTL = "NXCTL"

  BOTO = "BOTO"

  @staticmethod
  def types():
    """This method is used to list all supported interfaces.

    Returns:
      A list of interface types.
    """
    attributes = list(Interface.__dict__.keys())
    return [item for item in attributes if re.match("^[A-Z]", item)]

  @staticmethod
  def validate(interface_type):
    """This method is used to validate a given interface type.

    Args:
      interface_type(str): Interface type.

    Raises:
      NuTestValueError: When invalid interface_type is passed.
    """
    if interface_type not in Interface.types():
      raise NuTestValueError(
        "Invalid interface type passed %s. Expected values: %s."
        % (interface_type, Interface.types()), category=ErrorCategory.USAGE)
