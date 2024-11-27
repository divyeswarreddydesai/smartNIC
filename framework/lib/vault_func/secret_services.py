#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
"""
Base class for interfacing with Secret Storage Services.
"""
# pylint:disable=too-many-function-args

import abc
import threading
from framework.lib.vault_func.cache import DictCache

class SecretServices():
  """ Class to interface with secret storage service. """

  __singleton_lock = threading.Lock()
  __singleton_instance = None
  _cache = None

  def __init__(self, **kwargs):
    """ Init method. """
    cache_type = kwargs.get("cache_type", "dict")
    if cache_type == "dict":
      SecretServices._cache = DictCache()

  @classmethod
  def get_handle(cls, cache_type="dict"):
    """
    Get handle to secret services. This is a
    singleton implementation.
    Creation of secret services handle by concurrent
    threads are protected by a lock.
    Args:
      cache_type(str): Cache Type. Defaults to dictionary.

    Returns:
       Handle to the Vault instance.
    """
    # check for the singleton instance
    if not cls.__singleton_instance:
      with cls.__singleton_lock:
        if not cls.__singleton_instance:
          cls.__singleton_instance = cls(cache_type)
    # return the singleton instance
    return cls.__singleton_instance

  @classmethod
  def get_cache(cls, key, **kwargs):
    """
    Get value for the specified key version from the cache.

    Args:
      key(str): Username stored in the Vault.
      kwargs(dict):
        namespace(str): Vault namespace in which key resides.
        version(str): Key version. Defaults to 1.
    Returns:
      Value(str): Value for the specified key version.
    """
    return cls._cache.get(key, **kwargs)

  @classmethod
  def set_cache(cls, key, value, **kwargs):
    """
    Set value for the specified key version into the cache.

    Args:
      key(str): Username stored in the Vault.
      value(str): Value for the specified key version.
      kwargs(dict):
        namespace(str): Vault namespace in which key resides.
        version(str): Key version. Defaults to 1.
    Returns:
      Returns nothing on success and raises an exception on error.
    """
    return cls._cache.set(key, value, **kwargs)

  @abc.abstractmethod
  def get(self, key, **kwargs):
    """
    Get password from the vault.

    Args:
      key(str): Username stored in the Vault.
    kwargs (dict)-
      version(str): Password version.
    Returns:
      value(str): Password for the user.
    """


  @abc.abstractmethod
  def set(self, key, value, **kwargs):
    """
    Set password into the vault.

    Args:
      key(str): Username stored in the Vault.
      value(str): Password for the user.
    Returns:
      status - 0 for success and exception on failure.
    """
