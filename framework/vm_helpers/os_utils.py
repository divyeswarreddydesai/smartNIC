import ast
import base64
import collections
import fnmatch
import hashlib
import io
import json
import locale
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import time
import urllib.request, urllib.error, urllib.parse
import urllib.parse
import _strptime # Needed since the first use of strptime is not thread secure
from framework.vm_helpers.lib.package_handler import PackageHandler
from framework.vm_helpers.lib.version import Version as LooseVersion
from datetime import datetime
from framework.logging.log import ERROR, INFO, WARN
import jsonschema
import six
import dateutil.parser
import psutil
from bs4 import BeautifulSoup
from bson import json_util
from cryptography.fernet import Fernet
from jinja2 import Template
import ipaddress
from iptools.ipv4 import ip2long, long2ip
FILER_PROXY = "endor.dyn.nutanix.com"

GCP_VM_INTERNAL_TO_EXTERNAL_IP_MAP = {}


def validate_download(svm, file_url, file_location_on_svm,
                      is_sha256_present=False):
  """Validates downloaded file in SVM with SHA256 using public key.

  Args:
    svm(SVM): svm object to execute commands.
    file_url(str): full url of the original file to identify SHA256 path.
    file_location_on_svm(str): path of file downloaded in svm.
    is_sha256_present(bool): to identify if SHA256 is already present in SVM.

  Raises:
    NuTestError : On Validation failure.

  """
  sha_256_url = file_url + '.sha256'
  sha256_location_on_svm = file_location_on_svm + '.sha256'
  public_key = PackageHandler.get_resource_path(
    'framework/lib/keys/secure_artifacts_key.pem')
  public_key_location = '/tmp/' + os.path.basename(public_key)
  svm.rm(public_key_location)

  if not is_sha256_present:
    svm.rm(sha256_location_on_svm)
    svm.download_file(sha_256_url, local_path=sha256_location_on_svm)

  svm.transfer_to(public_key, '/tmp')
  validate_cmd = "openssl dgst -sha256 -verify {} -signature {} {}".format(
    public_key_location, sha256_location_on_svm, file_location_on_svm)
  response = svm.execute(validate_cmd, ignore_errors=True)
  svm.rm(public_key_location)
  svm.rm(sha256_location_on_svm)

  if response['status']:
    ERROR(response)
    svm.rm(file_location_on_svm)
    raise ERROR("SHA256 Validation failed")
  else:
    INFO("SHA256 Validation Success!")
    
def is_ipv6_address(ip):
  """
  checks whether ip is v4 or v6.

  Args:
    ip(str): ip address.

  Returns:
    bool: True if it's ipv6.

  """
  try:
    return isinstance(ipaddress.ip_address(u"%s" % ip), ipaddress.IPv6Address)
  except:
    return False

def get_highest_python_version(vm):
  """
  Get the highest python version from a given vm object. This is useful if the
  vm has various python versions installed and the 'python' command is
  either not present, or points to an old version.

  Args:
    vm (VM Object): VM object.

  Returns:
    str: Python command to use, like python or python2.7 or python3.9.
  """
  result = vm.execute("ls /usr/bin | grep python", ignore_errors=True)
  if not result['status']:
    highest = "0.0"
    for pver in result['stdout'].splitlines():
      pver = pver.strip()
      reg = re.search(r'^python(\S*\d+)$', pver)
      if reg:
        if LooseVersion(reg.group(1)) > LooseVersion(highest):
          highest = reg.group(1)
    if highest != "0.0":
      return "python{}".format(highest)
  return "python"

def get_rsa_pvt_key_from_encoded_str(encoded_key):
  """
  Method to get the private key object from the encoded key string.

  Args:
    encoded_key(str): Encoded key string.

  Returns:
    RSAKey: Private key object.
  """
  try:
    import paramiko
    decoded_key = base64.b64decode(encoded_key).decode()
    key_string = io.StringIO(decoded_key)
    key_obj = paramiko.RSAKey.from_private_key(key_string)
    return key_obj
  except Exception as exc:
    WARN("Failed to get private key from %s due to error: %s"
         % (encoded_key, str(exc)))
    return None