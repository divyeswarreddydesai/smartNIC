#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
"""
Module to cache vault credentials.
"""
# pylint: disable=inconsistent-return-statements

import abc
from framework.logging.log import DEBUG, ERROR

class Cache():
  """ Class to cache vault credentials, api keys etc."""

  @classmethod
  @abc.abstractmethod
  def get(cls, key, **kwargs):
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
    #pass

  @classmethod
  @abc.abstractmethod
  def set(cls, key, value, **kwargs):
    """
    Set value for the specified key version into the cache.

    Args:
      key(str): Username stored in the Vault.
      value(str): Value for the specified key version.
      kwargs(dict):
        namespace(str): Vault namespace in which key resides.
        version(str): Key version. Defaults to 1.
    Raises:
      Exception if the key with specified version already exists in the cache.
    """
    #pass


class DictCache(Cache):
  """ Class to implement a dictionary cache for
      vault credentials, api keys etc."""

  _cache = {}

  @classmethod
  def get(cls, key, **kwargs):
    """
    Get value for the specified key version from the cache.
    If no version is specified then return the value of the latest version.

    Args:
      key(str): Username stored in the Vault.
      kwargs(dict):
        namespace(str): Vault namespace in which key resides.
        version(str): Key version. Defaults to 1.
    Returns:
      Value(str): Value for the specified key version.
                  None if key is not in the cache.
    """
    namespace = kwargs.get("namespace", None)
    version = kwargs.get("version", None)
    if namespace in cls._cache:
      if key in cls._cache[namespace]:
        if version:
          if version in cls._cache[namespace][key]:
            DEBUG("Cache Hit. Value of key %s successfully"
                  " obtained from cache" % key)
            return cls._cache[namespace][key][version]
        else:
          # Return the latest value for the key if no version is specified
          DEBUG("Cache Hit. Returning the latest version value"
                " for the key %s" % key)
          version = sorted(cls._cache[namespace][key].keys())[-1]
          return cls._cache[namespace][key][version]

  @classmethod
  def set(cls, key, value, **kwargs):
    """
    Set value for the specified key version into the cache.

    Args:
      key(str): Username stored in the Vault.
      value(str): Value for the specified key version.
      kwargs(dict):
        namespace(str): Vault namespace in which key resides.
                        This is a mandatory argument.
        version(str): Key version. This is a mandatory argument.
    Raises:
      Exception if the key with specified version already exists in the cache
      or either namespace or version is not specified in the input.
    """
    namespace = kwargs.get("namespace", None)
    version = kwargs.get("version", None)
    if not namespace or not version:
      ERROR("Either namespace:%s or version:%s is not specified."
            % (namespace, version))
      raise Exception("Either namespace:%s or version:%s is not specified."
                      "Both namespace and version are mandatory arguments."
                      % (namespace, version))
    if namespace not in cls._cache:
      cls._cache[namespace] = {}
    if key not in cls._cache[namespace]:
      cls._cache[namespace][key] = {}
    if version not in cls._cache[namespace][key]:
      cls._cache[namespace][key][version] = value
    else:
      raise Exception("Key %s with specified version %s "
                      "already exists" % (key, version))
