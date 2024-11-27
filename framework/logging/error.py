#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: sunil.goyal@nutanix.com
#         bgangadharan@nutanix.com
"""This module defines NuTest base exception."""

#pylint: disable=broad-except,unused-argument,no-else-raise
import inspect
import os

import six

from framework.logging.log import ERROR, WARN
from framework.logging.exception_decoder import ExceptionDecoder
from framework.vm_helpers.lib.package_handler import PackageHandler

NUTEST_EXCEPTIONS_PATH = PackageHandler.get_resource_path(
  'framework/exceptions/__pycache__')
ACTIVE_STATE_FILE = "code_active_state.log"

class ExpError(Exception):
  """Base class for all NuTest exceptions.
  """

  def __new__(cls, message='', collector=None, **kwargs):
    """Object Creator for the base exception.

    Args:
        message(str): The exception message.
        collector(object): Collector object which implements collect method.

    Raises:
      BaseException: "Exceptions defined in exceptions folder should only be
                      inherited from NuTestError"
    """
    mod_path, is_nutest_child, exception_files = (
      _get_mod_path_and_nutest_child(cls))

    if mod_path in exception_files and not is_nutest_child:
      raise BaseException(
        "Exceptions defined in exceptions folder should only be "\
        "inherited from NuTestError")
    else:
      return super(ExpError, cls).__new__(cls, message, collector, **kwargs)

  def __init__(self, message='', collector=None, mute_exception_warning=False,
               category=None, **kwargs):
    """Constructor for the base framework exception.

      Args:
        message(str): The exception message.
        collector(object): Collector object which implements collect method.
        mute_exception_warning(bool): If True, ignores logging error message.
                                      Defaults to False.
       category(BaseErrorCategory): Category to which exception belongs to.
    """
    self.category = category
    if not mute_exception_warning:
      if isinstance(message, bytes):
        message = six.ensure_text(message, encoding="utf-8")
      else:
        message = str(message)
      WARN('The exception message is\n' + message)
    for key, value in kwargs.items():
      setattr(self, key, value)

    # Collect the context based logs
    # Note: We need to skip this for cases where
    # exceptions are not propagated up.
    if not os.environ.get("SKIP_COLLECTORS") == str(True):
      if collector and hasattr(collector, 'collect'):
        functor = getattr(collector, 'collect')
        try:
          functor()
        except Exception as err:
          ERROR("Unable to run the collector. %s" % str(err))
    super(ExpError, self).__init__(message)
    if "command" not in kwargs:
      self.command = None
    if "result" not in kwargs:
      self.result = {}

  @staticmethod
  def decode_exception():
    """Prints active state of the code during exceptions."""
    ExceptionDecoder.decode_exception(output_path=ACTIVE_STATE_FILE)

def _get_mod_path_and_nutest_child(cls):
  """This function provides module path of cls, verifies if cls is derived
  from NuTestError and list of exception files defined under exceptions
  folder/sub folders.

  Returns:
    (tuple): ModulePath, Flag indicating is nutest child, Exceptions
  """
  mod_path = inspect.getabsfile(cls)
  exception_files = []
  for dirname, _, filenames in os.walk(NUTEST_EXCEPTIONS_PATH):
    for filename in filenames:
      exception_files.append(os.path.abspath(
        os.path.join(dirname, filename)))
  class_bases = inspect.getmro(cls)
  is_nutest_child = False
  for klass in class_bases:
    if klass.__name__ == "NuTestError":
      is_nutest_child = True
  return mod_path, is_nutest_child, exception_files
