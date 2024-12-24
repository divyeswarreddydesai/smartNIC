# Copyright (c) 201g Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
#

"""This is the module for all interface constants.
"""
# pylint: disable=import-outside-toplevel

import os
from framework.vm_helpers.lib.package_handler import PackageHandler

# PRISM Credentials
PRISM_USER = "admin"
PRISM_DEFAULT_PASSWORD = "Nutanix/4u"
PRISM_PASSWORD = "Nutanix.123"
PRISM_PORT = "9440"
PRISM_PASSWORD_WITHOUT_PAM = "nutanix/4u"

NUTEST_PRISM_USER = 'nutest'
NUTEST_PRISM_PASSWORD = 'Nutanix.123'
NUTEST_PRISM_FIRST_NAME = 'nutest'
NUTEST_PRISM_LAST_NAME = 'admin'

ADMIN_PRISM_USER = 'admin'
ADMIN_PRISM_PASSWORD = 'Nutanix.123'

# SVM Credentials
SVM_USER = os.environ.get("SVM_USER", "nutanix")
SVM_PASSWORD = os.environ.get("SVM_PASSWORD", "RDMCluster.123")

# SSP Credentials
AD_DOMAIN_NAME = "qa.nutanix.com"
SSP_SERVICE_ACCOUNT = "ssp_admin"
SSP_USER = "ssp_admin"
SSP_PASSWORD = "nutanix/4u"

# Default path to private SSH key.'framework/interfaces/ssh/keys/nutanix'
KEY_FILE = PackageHandler.get_resource_path(
  'framework/interfaces/ssh/keys/nutanix')

# Active Directory
AD_ADMIN_USER = "administrator"
AD_ADMIN_PASWD = "nutanix/4u"

if os.environ.get("NUCLOUD_GCP"):
  AD_ZONE_NAME = "adgcp6.com"
  AD_SERVER_IP = "172.30.0.11"
  AD_BASE_DN = "DC=adgcp6,DC=com"
  AD_WORKGROUP_NAME = "ADGCP6"
  AD_FQDN_NAME = "ad2016-3.adgcp6.com"
elif os.environ.get("PLATFORM_TYPE") == "AWS":
  AD_ZONE_NAME = "filesawsad.com"
  AD_SERVER_IP = "10.53.67.91"
  AD_BASE_DN = "DC=filesawsad,DC=com"
  AD_WORKGROUP_NAME = "WIN-66TG3DUIMS3"
  AD_FQDN_NAME = "filesawsad.com"
else:
  AD_ZONE_NAME = "child4.afs.minerva.com"
  AD_SERVER_IP = "10.40.64.103"
  AD_BASE_DN = "DC=child4,DC=afs,DC=minerva,DC=com"
  AD_WORKGROUP_NAME = "CHILD4"
  AD_FQDN_NAME = "child4.afs.minerva.com"

# IDP Constants
IDP_ADMIN_USER = "xi_blruser1@nutanix.com"
IDP_ADMIN_PASSWORD = "@Nutanix.1"
IDP_USER_DEFAULT_PASSWORD = "@Nutanix1"
REDIRECT_URI = "https://{xi_url}/api/nutanix/v3/{callback_url}"
XI_PAIRING_URI = "https://{my_nutanix_domain}/api/v2/pairing"

# IDP Service Provider Constants
IDP_IP = "idp-test.nutanix.com"
IDP_CALLBACK_URL = "oauth/idp_callback"
IDP_REDIRECT_PATH = "oauth/idp_redirect_callback"
IDP_URL = "https://%s" % IDP_IP
IDP_CONTEXT_URL = "%s/nutanix/services/rest" % IDP_URL
IDP_API_USER = "xi"
IDP_API_PASSWORD = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"
DEFAULT_IDP_CALLBACK = "https://xi-cloud/callback"
ENV_TO_IDP_SERVER_MAP = {
  "demo-my.nutanix.com": {
    "idp_server": "idp-dev.nutanix.com",
    "client_id": "EwK4YJftwVADqxm7SuUtazf1SYIa",
    "secret_key": "32950_QpEXy_ZaeAnJw6fhlczmka"
  },
  "test-my.nutanix.com": {
    "idp_server": "idp-test.nutanix.com",
    "client_id": "fxoVT0uuZab3d1AqmOfbnUfJaM8a",
    "secret_key": "ZkDaqZhs_UttQfQyPHsVVc0osg8a",
    "nutest_iam_acc": "nutest_service_test"
  },
  "stage-my.nutanix.com": {
    "idp_server": "idp-stage.nutanix.com",
    "client_id": "fxoVT0uuZab3d1AqmOfbnUfJaM8a",
    "secret_key": "ZkDaqZhs_UttQfQyPHsVVc0osg8a",
    "nutest_iam_acc": "nutest_service_stage"
  },
  "my.nutanix.com": {
    "nutest_iam_acc": "nutest_service_prod"
  }
}

# ARISTA SWITCH CONSTANTS
ARISTA_SWITCH_USER = "admin"
ARISTA_SWITCH_PASSWORD = "admin"

# RPC Constants
CACHE_RPC_CLIENTS = True

# WINDOWS Credentials
WINDOWS_USER = "Administrator"
WINDOWS_PASSWORD = "nutanix/4u"

# CENTOS Credentials
CENTOS_USER = "nutanix"
CENTOS_PASSWORD = "nutanix/4u"

# WINDOWS Credentials
WINDOWS_USER = "Administrator"
WINDOWS_PASSWORD = "nutanix/4u"
RHEL_USER="root"
RHEL_PASSWORD="nutanix/4u"
# CENTOS Credentials
CENTOS_USER = "nutanix"
CENTOS_PASSWORD = "nutanix/4u"

DEFAULT_KUBE_CONFIG = "~/.kube/config"

class ClusterCreds:
  """Class for store cluster passwords"""

  SVM_PASSWORD = "nutanix/4u"
  HYPERVISOR_PASSWORD = "nutanix/4u"

  @classmethod
  def get_pvt_key(cls):
    """Get private key

    Returns:
      str: private key
    """
    if not os.environ.get("PVT_KEY"):
      return None
    from framework.lib.utils import get_rsa_pvt_key_from_encoded_str
    return get_rsa_pvt_key_from_encoded_str(os.environ.get("PVT_KEY"))
