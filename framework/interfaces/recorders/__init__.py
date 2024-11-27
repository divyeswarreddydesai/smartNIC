"""Package for recording stats into a database during execution.
"""
# Copyright (c) 2021 Nutanix Inc. All rights reserved.

# Author: sudharshan.dm@nutanix.com

from .null_recorder import NullRecorder
from .tinydb_recorder import TinyDBRecorder

_RECORDER = NullRecorder()

def set_recorder(**kwargs):
  """Set the recorder for the run.
  """
  global _RECORDER # pylint: disable = global-statement
  _RECORDER = TinyDBRecorder(**kwargs)

def get_recorder():
  """Obtain the recorder of the run.

  Returns:
    BaseStatRecorder
  """
  return _RECORDER
