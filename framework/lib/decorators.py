from functools import wraps
import os
import re
import time
from framework.logging.log import DEBUG, WARN
MAX_RETRIES = 5
MAX_SLEEP_INTERVAL = 10
def retry(*args, **kwargs):
  """
  Retry is a decorator method which can be used to simplify the task of adding
  retry behavior when a exception(can be specific too) or unwanted return
  values occurs on the function/method.

  Here are the cases you can try using this retry decorator:

  Case 1: Retry for all exceptions raised. Uses default max_retries and
  sleep_interval.

  @retry
  def func1():
    raise Exception

  Case 2: Retry only for specific exceptions. Also specify the retries and
  sleep interval values.

  @retry(exception_list=[KeyError, IOError], retries=10, sleep_interval=3)
  def func2(x):
    if x:
      raise ValueError
    else:
      raise KeyError

  Case 3: Retry for specific return values of function.

  @retry(return_value=5, retries=10, sleep_interval=3)
  def func3(y):
    return y

  It just retries when the func3 return value is 5, the decorator will not
  throw an exception.

  Case 4: Retry only for the return value and not for the default exception.

  @retry(return_value=5, exception_list=[], retries=10, sleep_interval=3)
  def func3(y):
    return y

  Case 5: Retry only when the raised exception contains any of the
          error msg listed in the except_err_msgs list.
  @retry(exception_err_msgs=["Cannot find snap id for snapshot",
                             "Failed to find Vdisk with id [0-9]+",
                             "CONCURRENT_REQUESTS_NOT_ALLOWED"], retries=4)
  def func5(**kw):
    # CODE
    return y

  Args:
    *args: the arguments is needed for taking the function name.

  kwargs:
    exception_list(list): List of exceptions for retrying
    retries(int): Number of times to retry.
    sleep_interval(int): Sleep interval in secs.
    return_value: Any return value.
    exception_err_msgs(list): List of error messages/regex patterns to retry for
                              Default: ()

  Returns:
    function: A wrapper function which will retry the actual function.
  """
  exception_list = kwargs.get('exception_list', [Exception])
  exeptions = () if not exception_list else tuple(exception_list)
  max_retries = kwargs.get('retries', MAX_RETRIES)
  sleep_interval = kwargs.get('sleep_interval', MAX_SLEEP_INTERVAL)
  return_value = kwargs.get('return_value')
  exception_err_msgs = kwargs.get('exception_err_msgs', ())

  def func_decorator(func):
    """Decorator for taking the function."""

    @wraps(func)
    def wrapper(*func_args, **func_kwargs):
      """Function wrapper."""

      custom_decorator = kwargs.get('custom_decorator_retries', '')
      custom_decorator_val = int(os.environ.get(custom_decorator, 0)) \
                                if custom_decorator else 0
      maximum_retries = func_kwargs.get('decorator_retries') or \
                        custom_decorator_val or max_retries
      for ii in range(maximum_retries):
        try:
          ret_value = func(*func_args, **func_kwargs)
          if 'return_value' not in kwargs or ret_value != return_value:
            return ret_value
          elif 'return_value' in kwargs:
            WARN('Function returned unwanted return values %s.' %
                 str(ret_value))
            WARN("Retrying in %s secs, Retry count: %s/%s" %
                 (sleep_interval, ii+1, maximum_retries))
        except exeptions as err:
          if ii == maximum_retries - 1:
            raise
          if (exception_err_msgs and not
              any(re.search(err_msg, str(err))
                  for err_msg in exception_err_msgs)):
            raise
          DEBUG("Encountered exception: %s, while executing: %s"
                % (err, func.__name__))
          DEBUG("Retrying in %s secs, Retry count: %s/%s" %
                (sleep_interval, ii+1, maximum_retries))
        time.sleep(sleep_interval)
      return ret_value
    return wrapper

  # Lets support both @retry and @retry() as valid syntax

  if len(args) == 1 and callable(args[0]):
    # Case where  @retry has no arguments. And args will be having only the
    # function.
    return func_decorator(args[0])

  else:
    # Case where @retry decorator has arguments.
    return func_decorator