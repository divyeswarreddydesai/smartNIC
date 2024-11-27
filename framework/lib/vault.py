#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
"""
Library methods for end users to set and retrieve
credentials from Secret Storage.
"""
import os

from framework.lib.vault_func.hcp_vault import HCPVault
from framework.lib.vault_func.local_vault import LocalVault

def access_secret_services(vault_type, cache_type="dict"):
  """
  Get a handle to secret services of the specified type.

   Args:
     vault_type(str): Vault Type.
     cache_type(str, optional): Cache Type.
   Returns:
     Handle to the Vault.
   Raises:
     Exception if the input vault type is not supported.
  """
  if not vault_type:
    vault_type = os.environ.get("VAULT_TYPE", None)
  print("vault type: %s" % vault_type)
  if vault_type == "HCP":
    handle = HCPVault.access_secret_services(cache_type=cache_type)
  elif vault_type == "LOCAL":
    handle = LocalVault.access_secret_services(cache_type=cache_type)
  else:
    raise Exception("Input vault: %s is not supported." % vault_type)
  return handle

def set_key(key, value, namespace, **kwargs):
  """
  Set password into the vault.

  Args:
    key(str): Username stored in the Vault
    value(str): Password for the user.
    namespace(str): Vault Namespace.
    kwargs (dict)-
      version(str): Password version.
      vault_type(str): Vault Type. Defaults to Hashicorp Vault.
  Returns:
      status: 0 for success and exception on failure.
  """
  vault_type = kwargs.get("vault_type", None)
  handle = access_secret_services(vault_type)
  return handle.set(key=key, value=value, namespace=namespace, kwargs=kwargs)

def get_key(key, namespace, **kwargs):
  """
  Get password from the vault.

  Args:
    key(str): Username stored in the Vault
    namespace(str): Vault Namespace.
    kwargs (dict)-
      vault_type(str): Vault Type. Defaults to Hashicorp Vault.
      version(str): key/Password version. Defaults to latest version.
  Returns:
      status: 0 for success and exception on failure.
  """
  vault_type = kwargs.get("vault_type", None)
  handle = access_secret_services(vault_type)
  return handle.get(key=key, namespace=namespace, kwargs=kwargs)
