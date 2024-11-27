"""Tracer abstraction for capturing HTTP requests and responses.
"""
# Author: sudharshan.dm@nutanix.com

class HTTPTracer:
  """Tracer for HTTP requests and responses.

  Sample Usage (with REST v4 entities):
    tracer = HTTPTracer()
    with tracer:
      entity.operation(param1=arg1, param2=arg2, tracer=tracer)
      request, response = tracer.main_pair
  """
  def __init__(self):
    """Initializer.
    """
    self._pairs = []
    self._main_pair = None

  def __enter__(self):
    """Entry Context Manager.

    Returns:
      type(self)
    """
    return self

  def __exit__(self, exc_type, exc_value, tb):
    """Exit Context Manager.

    Args:
      exc_type (type): Type of exception, if raised within the managed context.
      exc_value (BaseException): Exception object, if raised within the managed
        context.
      tb (traceback): Traceback of the exception, if raised within the
        managed context.
    """
    self.clear()

  @property
  def pairs(self):
    """Request-response pairs of the trace.

    Returns:
      [(requests.Request, requests.Response)]:
    """
    return self._pairs

  @property
  def main_pair(self):
    """The main request-response pair of the trace.

    Returns:
      (requests.Request, requests.Response):
    """
    return self._main_pair

  def add_pair(self, request, response):
    """Add a request-response pair to the tracer.

    Args:
      request (requests.Request): Request object.
      response (requests.Response): Response object.
    """
    self._pairs.append((request, response))

  def maybe_set_main_pair(self, index):
    """Set the main request-response pair of the trace if possible.

    Args:
      index (int): Index of the request-response pair to set as the main pair.
    """
    try:
      self._main_pair = self.pairs[index]
    except IndexError:
      pass

  def clear(self):
    """Clears the captured pairs and thus resets the tracer to a fresh state.
    """
    self._pairs = []
    self._main_pair = None
