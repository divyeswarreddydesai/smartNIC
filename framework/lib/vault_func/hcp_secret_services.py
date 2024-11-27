#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
"""
Implements the methods to interface with the Hashicorp Vault
key-value secret Storage.
"""
# pylint: disable=no-else-return

import os
from framework.lib.vault_func.secret_services import SecretServices
from framework.logging.log import DEBUG, ERROR, INFO
from framework.interfaces.http.http import HTTP

class HCPSecretServices(SecretServices):
  """ Class to interface with Hashicorp Vault Secret Storage service. """

  __userinfo = None

  def __init__(self, cache_type="dict"):
    """
    Initialize address of the Hashicorp Vault and set
    the authenticated token
    in the header which will be used for accessing Vault.
    Args:
        cache_type(str): Cache Type. Defaults to dictionary as cache.
    Raises:
      Exception if VAULT_ADDR or VAULT_TOKEN environment variables are not set.
    """
    super(HCPSecretServices, self).__init__(cache_type=cache_type)
    # Secret prefix for versioned secret storage ie. version 2 of the secret.
    self.kv_data_path_prefix = "data"
    # Metadata prefix for versioned secret storage ie. version 2 of the secret.
    self.kv_metadata_path_prefix = "metadata"
    self.base_url = os.environ.get("VAULT_ADDR", None)
    if not self.base_url:
      ERROR("VAULT_ADDR is not set in the environment."
            "To access Hashicorp Vault, address of the vault is required.")
      raise Exception("VAULT_ADDR is not set in the environment."
                      " Please set and export VAULT_ADDR environment variable.")
    self.header = {}
    vault_token = os.environ.get("VAULT_TOKEN", None)
    if vault_token:
      self.header["X-Vault-Token"] = vault_token
    else:
      ERROR("VAULT_TOKEN is not set in the environment. "
            "To access Hashicorp Vault, authenticated token "
            "from the vault is required.")
      raise Exception("VAULT_TOKEN is not set in the environment. "
                      "Please set and export VAULT_TOKEN.")

  def get(self, key, **kwargs):
    """
    Get password/key from the vault for user.

    Args:
      key(str): Username/Key stored in the Vault.
      kwargs (dict)-
        namespace(str): Vault Namespace.
        version(str): Key version. Defaults to latest version.
    Returns:
      value(str): Password for the user.
    Raises:
      Raise an exception if "key" or "namespace" is missing.
    """
    self._validate_input(key, **kwargs)
    namespace = kwargs.get("namespace", None)
    self.header["X-Vault-Namespace"] = namespace
    secret_endpoint = "%s/%s/%s/%s" % (self.base_url, namespace,
                                       self.kv_data_path_prefix, key)
    INFO("Getting value for key %s using endpoint %s with header %s"
         % (key, secret_endpoint, self.header))
    version = kwargs.get("version", None)
    if version:
      secret_endpoint += '?version={version}'.format(version=version)
    # check the cache first`
    value = super(HCPSecretServices, self).\
      get_cache(key, namespace=namespace, version=version)
    if value:
      DEBUG("Successfully retrieved value for the key %s "
            "from local cache" % key)
      return value
    else:
      http = HTTP()
      response = http.get(url=secret_endpoint, headers=self.header,
                          retry_on_auth_failures=True)
      DEBUG("Response: %s" % response.json())
      if response.status_code == 200:
        DEBUG("Successfully retrieved value for the key %s "
              "from hashicorp vault secret storage." % key)
        content = response.json()['data']["data"]
        if not version:
          version = response.json()['data']["metadata"]["version"]
        super(HCPSecretServices, self).\
          set_cache(key, content[key],
                    namespace=namespace, version=version)
        return content[key]
      else:
        ERROR("Retrieving key %s from hashicorp vault secret storage"
              " failed with status: %d" % (key, response.status_code))
        raise Exception("Retrieving key %s from hashicorp secret storage"
                        " vault failed with status: %d"
                        % (key, response.status_code))

  def get_version(self, key, **kwargs):
    """
    Get password/key version from the vault for specified key.

    Args:
      key(str): Username/Key stored in the Vault.
      kwargs (dict)-
        namespace(str): Vault Namespace.
    Returns:
      version(str):  Version of the key.
    Raises:
      Raise an exception if "key" or "namespace" is missing.
    """
    self._validate_input(key, **kwargs)
    namespace = kwargs.get("namespace", None)
    secret_endpoint = "%s/%s/%s/%s" % (self.base_url, namespace,
                                       self.kv_data_path_prefix, key)
    INFO("Getting value for key %s using endpoint %s with header %s"
         % (key, secret_endpoint, self.header))
    http = HTTP()
    self.header["X-Vault-Namespace"] = namespace
    response = http.get(url=secret_endpoint, headers=self.header)
    DEBUG("Response: %s" % response.json())
    if response.status_code == 200:
      DEBUG("Successfully retrieved value for the key %s "
            "from hashicorp vault secret storage." % key)
      version = response.json()['data']['metadata']["version"]
      return version
    else:
      ERROR("Retrieving key %s from hashicorp vault secret storage"
            " failed with status: %d" % (key, response.status_code))
      raise Exception("Retrieving key %s from hashicorp secret storage"
                      " vault failed with status: %d"
                      % (key, response.status_code))

  def set(self, key, value, **kwargs):
    """
    Set key and value into the Vault.

    Args:
      key(str): Username/key stored in the Vault.
      value(str): Password/value for the user/key.
      kwargs (dict)-
        namespace(str): Vault Namespace.
    Returns:
      status: 0 for success and exception on failure.
    Raises:
      Raise an exception if "key" or "namespace" is missing.
    """
    self._validate_input(key, **kwargs)
    namespace = kwargs.get("namespace", None)
    if not value:
      raise Exception("Value is missing."
                      " Please specify both key and value.")

    self.header["X-Vault-Namespace"] = namespace
    secret_endpoint = "%s/%s/%s/%s" % (self.base_url, namespace,
                                       self.kv_data_path_prefix, key)
    INFO("Setting value for key %s using endpoint %s with header %s"
         % (key, secret_endpoint, self.header))
    data = {"data": {key: value}}
    http = HTTP()
    response = http.post(url=secret_endpoint, headers=self.header, json=data,
                         retry_on_auth_failures=True)
    DEBUG("Response: %s" % response.json())
    if response.status_code == 200 or response.status_code == 204:
      DEBUG("Successfully stored value for the key %s "
            "into hashicorp vault secret storage" % key)
      metadata = self.get_user_info()
      self.set_metadata(secret_path="%s/%s" % (namespace, key),
                        latest_metadata=metadata)
      version = self.get_version(key, namespace=namespace)
      super(HCPSecretServices, self).\
        set_cache(key, value, namespace=namespace,
                  version=version)
      return 0
    else:
      ERROR("Setting key %s into hashicorp vault secret storage"
            " failed with status: %d" % (key, response.status_code))
      raise Exception("Setting key %s into hashicorp secret storage"
                      " vault failed with status: %d"
                      % (key, response.status_code))

  def set_metadata(self, secret_path, latest_metadata, **kwargs):
    """
    Set metadata for the specified path in the Vault.

    Args:
      secret_path(str): Vault path.
      latest_metadata(dict): Metadata to set.
      kwargs (dict): Keyword Args.
    Returns:
      status: 0 for success and exception on failure.
    Raises:
      Raise an exception if setting metadata failed.
    """
    payload = {
      'custom_metadata': latest_metadata
    }
    path, key = secret_path.rsplit("/", 1)
    secret_endpoint = "%s/%s/%s/%s" % (self.base_url, path,
                                       self.kv_metadata_path_prefix, key)
    INFO("Setting metadata value at endpoint %s with payload %s"
         % (secret_endpoint, payload))
    version = kwargs.get("version", None)
    if version:
      secret_endpoint += '?version={version}'.format(version=version)
    http = HTTP()
    response = http.post(url=secret_endpoint, headers=self.header, json=payload)
    DEBUG("Response: %s" % response)
    if response.status_code == 200 or response.status_code == 204:
      DEBUG("Successfully stored metadata "
            "into hashicorp vault secret storage")
      return 0
    else:
      ERROR("Setting metadata into hashicorp vault secret storage"
            " failed with status: %d" % response.status_code)
      raise Exception("Setting metadata into hashicorp vault secret storage"
                      " failed with status: %d" % response.status_code)

  def get_user_info(self):
    """
     Lookup token and retrieve user info.
     Returns:
       Returns a dictionary containing user info or
       None in case of error.
       User info includes user display name and entity id.
    """
    if not HCPSecretServices.__userinfo:
      content = self.lookup_vault_token()
      display_name = content["display_name"]
      if "-" in display_name:
        display_name = display_name.split("-")[-1]
      user_info = {}
      user_info["owner_name"] = display_name
      user_info["entity_id"] = content["entity_id"]
      HCPSecretServices.__userinfo = user_info
    return HCPSecretServices.__userinfo

  def lookup_vault_token(self):
    """
     Lookup vault token.
     Returns:
       Content (dict) of the vault token.
    """
    url = self.base_url + "/auth/token/lookup-self"
    http = HTTP()
    self.header.pop('content-type', None)
    response = http.get(url=url, headers=self.header)
    DEBUG("Token lookup information: %s" % response.json())
    if response.status_code == 200:
      DEBUG("Successfully looked up token information")
      content = response.json()['data']
    return content

  def _validate_input(self, key, **kwargs):
    """
    Validate input arguments.

    Args:
      key(str): Username/Key stored in the Vault.
      kwargs (dict)-
        namespace(str): Vault Namespace.
    Raises:
      Raise an exception if "key" or "namespace" is missing.
    """
    if not key:
      raise Exception("Key is missing. Please specify key"
                      " in the secret services.")
    namespace = kwargs.get("namespace", None)
    if namespace:
      self.header['X-Vault-Namespace'] = namespace.split("/")[0]
    else:
      raise Exception("Namespace in Secret Services is missing. "
                      "Please pass Namespace in Hashicorp Vault from which"
                      " to retrieve the key.")
