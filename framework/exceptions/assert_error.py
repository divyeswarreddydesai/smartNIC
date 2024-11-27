#
# Copyright (c) 2017 Nutanix Inc. All rights reserved.
#
# Author: iskrena.georgie@nutanix.com
"""This module defines validation errors."""

from framework.exceptions.nutest_error import NuTestError

class TrueExpectedError(NuTestError):
  """Class for True expected errors."""

class FalseExpectedError(NuTestError):
  """Class for False expected errors."""

class NoneError(NuTestError):
  """Class for None value errors."""

class NoneExpectedError(NuTestError):
  """Class for None expected errors."""

class MissingKeyError(NuTestError):
  """Class for missing key in dictionary errors."""

class HasKeyError(NuTestError):
  """Class for unexpected key in dictionary errors."""

class TypeMismatchError(NuTestError):
  """Class for value type errors."""

class MismatchError(NuTestError):
  """Class for value mismatch errors."""

class LessExpectedError(NuTestError):
  """Class for less expected errors."""

class GreaterExpectedError(NuTestError):
  """Class for greater expected errors."""

class UnknownRelationError(NuTestError):
  """Class for unknown relation errors."""

class ListExpectedError(NuTestError):
  """Class for list expected errors."""

class NotInError(NuTestError):
  """Class for value not in list errors."""

class NotCloseError(NuTestError):
  """Class for values not close errors."""

class InvalidValueError(NuTestError):
  """Class for invalid value errors."""
