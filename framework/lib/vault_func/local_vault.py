#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
"""
   Module to create and/or return Local Vault Secret store handle.
"""
from framework.lib.vault_func.vaultfactory import VaultFactory
from framework.lib.vault_func.local_secret_services import LocalSecretServices

class LocalVault(VaultFactory):
  """ Class to create/get an instance of Local Vault. """

  @classmethod
  def access_secret_services(cls, **kwargs):
    """
    Return a handle to Local Secret Store.
    Args:
      kwargs(dict): Arguments dict.
    Returns:
       Handle to Local Secret Services.
    """
    cache_type = kwargs.get("cache_type", "dict")
    return LocalSecretServices.get_handle(cache_type=cache_type)
