"""Python module implementing a wrapper over the requests.Session class.

Copyrights (c) Nutanix Inc. 2015

Author: bgangadharan@nutanix.com
"""
# pylint: disable=invalid-name,unused-variable,broad-except,import-error,no-name-in-module
# pylint: disable=too-many-branches,too-many-locals,import-outside-toplevel
# pylint: disable=too-many-statements,redefined-builtin,no-else-raise, ungrouped-imports
"""Package for recording stats into a database during execution.
"""



import json
import os
import time
from urllib.parse import urlparse
from functools import wraps

from requests import Session
from requests.exceptions import ConnectionError, ReadTimeout

# from framework.exceptions.nutest_error import NuTestError
# from framework.lib.decorators import handle_exception
from framework.logging.log_masking import is_sensitive_api, get_masked_dict
from framework.logging.error import ExpError
try:
  from requests.packages.urllib3 import disable_warnings

  disable_warnings()
except Exception:  # pragma: no cover
  pass
import traceback

# from framework.lib.error_categorisation import ErrorCategory
from framework.logging.log import DEBUG, WARN,ERROR
from framework.interfaces.recorders import get_recorder


def handle_exception(**kwargs):
  """
  Decorator to handle exceptions for any method.

  Kwargs:
    exception_type(obj): exception to be raised.
                         Defaults to NuTestError.
    error_message(str): error message if need to be specified.
    category_type(obj): Error category.

  Returns:
    (callable): Decorated func.


  """
  exception_type = kwargs.get('exception_type', ExpError)
  error_message = kwargs.get('error_message', '')
  category_type = kwargs.get('category_type', None)

  def func_decorator(func):
    """Decorator for taking the function."""

    @wraps(func)
    def wrapper(*func_args, **func_kwargs):
      """Function wrapper."""
      try:
        ret_value = func(*func_args, **func_kwargs)
      except ExpError:
        raise
      except Exception as err:
        ERROR(traceback.format_exc())
        if category_type:
          raise exception_type(error_message+"\nError : {}".format(err),
                               category=category_type)
        raise exception_type(error_message + "\nError : {}".format(err))
      return ret_value
    return wrapper

  return func_decorator
class HTTP:
  """This class implements a simple wrapper over the requests session.
  This class adds functionalities like retries and timeouts for the operations.
  """

  NO_RETRY_HTTP_CODES = [400, 404, 500, 502]

  def __init__(self, **kwargs):
    """Default constructor.
    Args:
      kwargs(dict): Accepts following arguments:
        timeout(optional, int): Max seconds to wait before HTTP connection
        times-out. Default 30 seconds.
        retries (optional, int): Maximum number of retires. Default: 5.
        retry_interval (optional, int): Time to sleep between retry intervals.
         Default: 5 seconds.

    Returns:
      None.
    """
    self._session = Session()
    self._timeout = kwargs.get('timeout', 30)
    self._retries = kwargs.get('retries', 5)
    self._retry_interval = kwargs.get('retry_interval', 30)

  def set_bearer_token(self, token):
    """Set an authorization bearer token for all requests.

    Args:
      token (str): Bearer token
    """
    self._session.headers["Authorization"] = "Bearer %s" % token

  def unset_bearer_token(self):
    """Unset the authorization bearer token for all requests.
    """
    del self._session.headers["Authorization"]

  def delete(self, url, **kwargs):
    """This is a wrapper method over the delete method.

    Args:
      url (str): The URL to for the Request
      kwargs (dict): Keyword args to be passed to the requests call.

    Returns:
      (response): The response object
    """
    return self._send('delete', url, **kwargs)

  def get(self, url, **kwargs):
    """This is a wrapper method over the get method.

    Args:
      url (str): The URL to for the Request
      kwargs (dict): Keyword args to be passed to the requests call.

    Returns:
      (response): The response object
    """
    return self._send('get', url, **kwargs)

  def head(self, url, **kwargs):
    """This is a wrapper method over the head method.

    Args:
      url (str): The URL to for the Request
      kwargs (dict): Keyword args to be passed to the requests call.

    Returns:
      (response): The response object
    """
    return self._send('head', url, **kwargs)

  def post(self, url, **kwargs):
    """This is a wrapper method over the post method.

    Args:
      url (str): The URL to for the Request
      kwargs (dict): Keyword args to be passed to the requests call.

    Returns:
      (response): The response object
    """
    return self._send('post', url, **kwargs)

  def put(self, url, **kwargs):
    """This is a wrapper method over the put method.

    Args:
      url (str): The URL to for the Request
      kwargs (dict): Keyword args to be passed to the requests call.

    Returns:
      (response): The response object
    """
    return self._send('put', url, **kwargs)

  def patch(self, url, **kwargs):
    """This is a wrapper method over the patch method.

    Args:
      url (str): The URL to for the Request
      kwargs (dict): Keyword args to be passed to the requests call.

    Returns:
      (response): The response object
    """
    return self._send('patch', url, **kwargs)

  @handle_exception(exception_type=ExpError, raise_exception=True
                  )
  def send(self, method, url, tracer=None, **kwargs):
    """This is a wrapper method over HTTP methods.

    Args:
      method (str): The http method type.
      url (str): The URL to for the Request
      tracer (HTTPTracer): Tracer object for capturing request-response
        exchanges.
      kwargs (dict): Keyword args to be passed to the requests call.
        retries (int): The retry count in case of HTTP errors.
                       Except the codes in the list NO_RETRY_HTTP_CODES.
        retry_on_auth_failures (bool): Retry for 401 and 403 status codes.
                                       Defaults to False.

    Returns:
      (response): The response object

    Raises:
      NuTestHTTPError, NuTestInterfaceTransportError
    """
    method = method.lower()
    debug = kwargs.get('debug', True)
    kwargs['verify'] = kwargs.get('verify', False)
    if 'debug' in kwargs:
      del kwargs['debug']
    if 'timeout' not in kwargs:
      kwargs['timeout'] = self._timeout
    # Increasing the timeout for Nested environments
    if os.environ.get('NESTED_AHV') == "1" and kwargs['timeout'] is not None:
      kwargs['timeout'] *= 3
    if 'json' in kwargs:
      kwargs['data'] = json.dumps(kwargs['json'])
      content_dict = {'content-type': 'application/json'}
      kwargs.setdefault('headers', {})
      kwargs['headers'].update(content_dict)
      del kwargs['json']
    func = getattr(self._session, method)
    response = None

    retries = kwargs.pop("retries", None)
    retry_interval = kwargs.pop("retry_interval", self._retry_interval)
    retry_count = retries if retries else self._retries
    retry_on_auth_failures = kwargs.pop('retry_on_auth_failures', False)
    for ii in range(retry_count):
      request_doc_id = get_recorder().add_http_request(method, url)
      if debug:
        DEBUG(">>%s %s : %s" % (method.upper(), url, kwargs))
      try:
        response = func(url, **kwargs)
        if kwargs.get('params'):
          DEBUG("The request url sent: %s" % response.request.url)

      except (ConnectionError, ReadTimeout) as e:
        WARN("Request failed with error: %s" % e)
        # Remove HTTP requests that fail with transport layer errors.
        get_recorder().remove_http_request(request_doc_id)
        if ii != retry_count - 1:
          time.sleep(retry_interval)
        continue
      else:
        if tracer:
          tracer.add_pair(request=response.request, response=response)
      finally:
        # This is not a complete session close. It actually clears all cached
        # connections, that are currently not in use. It will NOT affect
        # connections that are in use. It takes care of threaded execution too.
        self._session.close()

      if debug:
        response_data = response.text
        if is_sensitive_api(url):
          response_data = get_masked_dict(response, is_json=True)
        DEBUG("<<%s:%s" % (response.status_code, response_data))
      get_recorder().add_http_response(request_doc_id, response)

      if response.ok:
        return response
      if response.status_code in [401, 403] and not retry_on_auth_failures:
        raise ExpError(
          'HTTP Auth Failed %s %s' % (method, url), response=response)
      elif response.status_code == 409:
        raise ExpError('HTTP conflict with the current state of the '
                              'target resource %s %s' % (method, url),
                              response=response)
      elif response.status_code in self.NO_RETRY_HTTP_CODES:
        break
      if ii != retry_count - 1:
        time.sleep(retry_interval)

    if response is not None:
      msg = 'HTTP %s %s failed. Response: %s' % (method, url, response)
      if hasattr(response, "text") and response.text:
        msg = "\n".join([msg, response.text])
      raise ExpError(msg, HTTPCollector(urlparse(url).hostname),
                            response=response)
    else:
      raise ExpError("Failed to make the HTTP request %s "
                                          "%s" % (method, url))

  # For backward compatibility.
  _send = send


class HTTPCollector:
  """This is the log collector for this module"""

  def __init__(self, host=None):
    """Constructor for the log collector class.

    Args:
      host (str): Host name or IP.
    """
    self._host = host

  def collect(self):
    """Implements the collection of ping traces.
    """
    # Using lazy import as a workaround for cyclic import with utils library.
    from framework.lib.utils import ping

    if self._host:
      ping(self._host, use_nmap=True, retries=1)
