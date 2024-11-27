#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
"""
  Base class for interfacing with Local Secret Storage Services.
"""
import os
import json
import platform
import wget
from framework.lib.vault_func.secret_services import SecretServices
import urllib.request, urllib.error, urllib.parse
import urllib.parse
from framework.logging.log import DEBUG, ERROR,INFO
from framework.consts import \
    CREDENTIALS_FILE_PATH, DECRYPT_BINARY_PATH, LOCAL_DECRYPT_BINARY_PATH
from framework.lib.lock import lock_file
if platform.system() == 'Darwin':
  from framework.consts import \
    LOCAL_DECRYPT_BINARY_VERSION, DECRYPT_BINARY_FILER_VERSION_PATH
def download(url, output_dir=None, block_size=64*1024):
  """Download the given url to a file in output_dir.

  The file will by named using the url:
    url = http://127.0.0.1:8080/path/to/file
    name = file

  Args:
    url (str): Url to download file from
    output_dir (str): Location to download file to. If not provided, defaults to
      a temporary directory. Recommended to use out_dir.
    block_size (int): Size in bytes to read and write at a time.
      Default to 64KB blocks.

  Returns:
    str: Path to the downloaded file.
  """
  import tempfile

  if not output_dir:
    output_dir = tempfile.mkdtemp()

  file_name = os.path.join(output_dir, url.split('/')[-1])
  file_name = os.path.normpath(file_name)
  if os.path.exists(file_name):
    INFO("File %s already exists, returning." % file_name)
    return file_name

  resp = urllib.request.urlopen(url)
  INFO("Downloading %s to %s" % (url, file_name))

  with open(file_name, 'wb') as out_file:
    INFO("Starting download.")
    while True:
      block = resp.read(block_size)
      if not block:
        break
      out_file.write(block)

  INFO("Download finished.")
  return file_name
class LocalSecretServices(SecretServices):
  """ Class to interface with Local Secret Storage Service. """

  __userinfo = None
  LOCAL_VAULT_LOCK_FILE = "local_vault_lock"

  # pylint: disable=import-outside-toplevel
  def __init__(self, cache_type="dict"):
    """
    Download encrypted credential file and decrypt it and
    set the creds info in the cache.
    Args:
      cache_type(str): Cache Type. Defaults to dictionary as cache.
    Raises:
      Exception if changing tool execution mode or
                decrypting credentials file or
                setting key in the cache fails.
    """
    from framework.vm_helpers.linux_os import LinuxOperatingSystem
    # from framework.operating_systems.operating_system.linux_operating_system \
    #   import LinuxOperatingSystem
    # from framework.lib.utils import download
    super(LocalSecretServices, self).__init__(cache_type=cache_type)
    with lock_file(LocalSecretServices.LOCAL_VAULT_LOCK_FILE, timeout=180,
                   debug=True):
      # Remove existing decrypt binary
      if not platform.system() == 'Darwin':
        try:
          os.remove(LOCAL_DECRYPT_BINARY_PATH)
        except OSError:
          pass
      nutest_temp_path = os.path.dirname(LOCAL_DECRYPT_BINARY_PATH)
      # if "tmp" dir does not exist in NUTEST_PATH, then create it
      cmd = "mkdir -p %s" % nutest_temp_path
      response = LinuxOperatingSystem.local_execute(cmd)
      if response["status"] != 0:
        raise Exception("Creating tmp directory %s failed with error %s"
                        % (nutest_temp_path,
                           response["stderr"]))
      if not os.path.exists(LOCAL_DECRYPT_BINARY_PATH):
        download(DECRYPT_BINARY_PATH, nutest_temp_path)
        cmd = "chmod +x %s" % LOCAL_DECRYPT_BINARY_PATH
        response = LinuxOperatingSystem.local_execute(cmd)
        if response["status"] != 0:
          raise Exception("Changing %s mode to execute failed with error %s"
                          % (LOCAL_DECRYPT_BINARY_PATH, response["stderr"]))
        if platform.system() == 'Darwin':
          # install the version file for Mac platform only.
          wget.download(DECRYPT_BINARY_FILER_VERSION_PATH,
                        out=os.path.dirname(LOCAL_DECRYPT_BINARY_VERSION))

      credential_file_paths = [CREDENTIALS_FILE_PATH]
      if os.environ.get("LOCAL_VAULT_CREDS_PATHS", None):
        credential_file_paths.extend(
          os.environ.get("LOCAL_VAULT_CREDS_PATHS").split(","))

      for creds_file_path in credential_file_paths:
        # Remove existing local creds path
        try:
          os.remove(os.path.join(nutest_temp_path,
                                 os.path.basename(creds_file_path)))
        except OSError:
          pass
        creds_file_path = download(creds_file_path, nutest_temp_path)
        cmd = "%s -f %s" % (LOCAL_DECRYPT_BINARY_PATH, creds_file_path)
        response = self._execute_cmd(cmd)
        os.remove(creds_file_path)
        key_store = json.loads(response["stdout"].replace("'", "\""))
        for namespace in key_store:
          for key in key_store[namespace]:
            for version in key_store[namespace][key]:
              self.set(key, value=key_store[namespace][key][version],
                       namespace=namespace, version=version)

      if not platform.system() == 'Darwin':
        os.remove(LOCAL_DECRYPT_BINARY_PATH)

  def get(self, key, **kwargs):
    """
    Get password/key from the vault for the specified user.

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
    if not key:
      raise Exception("Key is missing. Please specify key"
                      " in the secret services.")
    namespace = kwargs.get("namespace", None)
    if not namespace:
      raise Exception("Namespace in Secret Services is missing. "
                      "Please pass namespace to retrieve the key.")
    version = kwargs.get("version", None)
    value = super(LocalSecretServices, self). \
      get_cache(key, namespace=namespace, version=version)
    if not value:
      raise Exception("Retrieving key %s from the cache failed." % key)
    return value

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
      Raise an exception if "key", "value" or "namespace" is missing.
    """
    namespace = kwargs.pop("namespace", None)
    if not key or not value or not namespace:
      raise Exception("Key, Value or Namespace is missing."
                      " Specified values for key %s, value %s, namespace %s."
                      % (key, value, namespace))
    super(LocalSecretServices, self).\
        set_cache(key, value, namespace=namespace, **kwargs)

  def _execute_cmd(self, cmd, retries=3): #pylint: disable=no-self-use
    """
    Retry command execution with logging.

    Args:
      cmd(str): Command to execute.
      retries(int): Command retries.

    Returns:
      response(dict): Command execution result.

    Raises:
      Raise an exception if command execution failed after specified retries.
    """
    from framework.operating_systems.operating_system.linux_operating_system \
      import LinuxOperatingSystem
    attempt = 1
    while attempt <= retries:
      DEBUG("Attempt %d of executing cmd %s" % (attempt, cmd))
      response = LinuxOperatingSystem.local_execute(cmd)
      if response["status"] == 0:
        return response
      ERROR("Decrypting credentials info failed with error %s"
            % response["stderr"])
      DEBUG("Log the permissions of the local binary %s"
            % LOCAL_DECRYPT_BINARY_PATH)
      lcmd = "ls -l %s" % LOCAL_DECRYPT_BINARY_PATH
      response = LinuxOperatingSystem.local_execute(lcmd)
      attempt += 1
    raise Exception("Decrypting credentials info failed after %d retries"
                    " with error %s" % (retries, response["stderr"]))
