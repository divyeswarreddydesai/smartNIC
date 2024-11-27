#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
"""
   Module to create and/or return Hashicorp Vault Secret store
   handle which will be used to perform operation on hashicorp vault.
"""
from framework.lib.vault_func.vaultfactory import VaultFactory
from framework.lib.vault_func.hcp_secret_services import HCPSecretServices

class HCPVault(VaultFactory):
  """ Class to create/get an instance of Hashicorp Vault. """

  @classmethod
  def access_secret_services(cls, **kwargs):
    """
    Return a handle to Hashicorp Vault Secret Store.
    Args:
      kwargs(dict): Arguments dict.
    Returns:
       Handle to Hashicorp Vault Secret Services.
    """
    cache_type = kwargs.get("cache_type", "dict")
    return HCPSecretServices.get_handle(cache_type=cache_type)
