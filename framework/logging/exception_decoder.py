# Copyright (c) 2017 Nutanix Inc. All rights reserved.
#
# Author: buchibabu.chennupati@nutanix.com
"""Helper module to print the active state of the code during exceptions."""
# pylint: disable=broad-except

import os
import sys
import pprint
import inspect
import traceback
from framework.logging.log import INFO, WARN


class ExceptionDecoder:
  """Helper to decode exceptions during exceptions."""

  @staticmethod
  def decode_exception(output_path=None, exc_info_obj=None):
    """Prints the active state of the code when an exception occured.

    Args:
      output_path(str): The absolute or relative path where active state of code
      when error occured, is to be stored.If relative path is passed, it will be
      found in NUTEST_LOGDIR.
      exc_info_obj(tuple): tuple of exception info for cases where exception
      logging happens outside exception block as stack frame is not accessible.
    """
    if not output_path:
      abs_output_path = None
    elif os.path.isabs(output_path):
      abs_output_path = output_path
    else:
      abs_output_path = os.path.join((os.environ['NUTEST_LOGDIR']), output_path)

    try:
      e_type, e_value, tb = sys.exc_info()
      if not (e_type or e_type or tb) and exc_info_obj:
        e_type, e_value, tb = exc_info_obj
      trace = traceback.format_exception(e_type, e_value, tb)
      info = []
      while tb:
        info.append("-" * 80)
        info.append("Code: <%s> in File: %s" % (
          tb.tb_frame.f_code.co_name,
          tb.tb_frame.f_code.co_filename))
        info.append(ExceptionDecoder._get_marked_code(tb.tb_frame))
        info.append("Locals: %s" % pprint.pformat(tb.tb_frame.f_locals))

        if 'self' in tb.tb_frame.f_locals and hasattr(tb.tb_frame.f_locals[
            'self'], '__dict__'):
          info.append("Locals.self: %s" % pprint.pformat(
            tb.tb_frame.f_locals['self'].__dict__))

        tb = tb.tb_next
      if info:
        info.append("\nException trace: ")
        info.append(''.join(trace))
        info.append("-" * 80)

        if abs_output_path:
          with open(abs_output_path, "a") as output_file:
            output_file.write("\n".join(info))
          INFO("Active state of the code during exception can be found at %s"
               %output_path)
        else:
          WARN("Active state of the code during exception:\n%s\n" %
               "\n".join(info))
    except Exception as error:
      WARN("Could not print active state of the code during exception:\n%s" %
           repr(error))

  @staticmethod
  def _get_marked_code(frame):
    """
    Marks the line where the exception happened and returns the code.

    Args:
      frame(frame): The frame whose code has to be marked and numbered

    Returns:
      str: Marked and line-numbered source code.
    """
    marker = '--->'
    start_lno = frame.f_code.co_firstlineno
    exc_lno = inspect.getframeinfo(frame)[1]
    src = inspect.getsourcelines(frame)[0]

    processed_lines = [
      "{0:4s} {1:4d} {2}".format(marker if lno == exc_lno else '', lno, l)
      for lno, l in enumerate(src, start=start_lno)
      ]

    exc_idx = exc_lno - start_lno - 1
    processed_lines = processed_lines[exc_idx - 5 if exc_idx > 5 else 0 :
                                      exc_idx + 5]

    return ''.join(processed_lines)
