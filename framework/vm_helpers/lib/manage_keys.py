#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com

"""Python module for managing Keys.
   Provides interface for dynamically retrieving keys
   from the Vault and generating key files.
"""
import tempfile
import threading

from framework.lib.vault import get_key

class ManageKeys():
  """ Class to manage Nutanix keys. """
  _cache = {}
  _ssh_key = "nutanix.pvt.key"
  _lock = threading.Lock()

  @classmethod
  def create_key_file(cls, key, namespace="framework", cache=True):
    """
    Gets key file from the cache if it exists else creates key file
    dynamically and adds it to the cache.

    Args:
      key(str): key to retrieve.
      namespace(str): Vault namespace in which key resides.
      cache(str): If True, cache is searched before generating file.
                  If False, cache is bypassed.
    Returns:
      key_file(str): File containing the requested key.
    """
    key_file = None
    if cache:
      key_file = cls._cache.get(key, None)
    if not key_file:
      with cls._lock:
        key_file = cls._cache.get(key, None)
        if not key_file:
          key_file_handle = tempfile.NamedTemporaryFile(delete=False)
          key_file_handle.write(get_key(key=key, namespace=namespace).encode())
          key_file = cls._cache[key] = key_file_handle.name
    return key_file

  @classmethod
  def get_ssh_keys(cls, key=None, namespace="nutest/framework", cache=True):
    """ Get private SSH keys. Default is nutanix SSH keys.
    Args:
      key(str): key to retrieve.
      namespace(str): Vault namespace in which key resides.
      cache(str): If True, cache is searched before generating file.
                  If False, cache is bypassed.
    Returns: SSH private key file path.
    """
    if not key:
      key = cls._ssh_key
    return cls.create_key_file(cls._ssh_key, cache=cache,
                               namespace=namespace)
