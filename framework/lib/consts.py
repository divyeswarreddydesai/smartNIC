# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: bgangadharan@nutanix.com
#
"""This is the module for all common lib constants.
"""
import os
from framework.logging.error import ExpError
# from framework.lib.error_categorisation import ErrorCategory
from framework.vm_helpers.lib.package_handler import PackageHandler

UNDEFINED_METADATA_FIELD = 'UNDEFINED'

class DNSServers:
  """
  Class for constants to represent DNS Servers in various labs.
  """
  PHX = ["10.40.64.15", "10.40.64.16"]
  DRT = ["10.4.8.15", "10.4.8.16"]
  BLR = ["10.136.17.15", "10.136.17.16"]
  RTP = ["10.60.1.230"]
  AMSTERDAM = ["10.64.2.10", "10.64.2.11"]
  GCP = ["169.254.169.254", "8.8.8.8"]

DNS_SERVER_MAP = {
  "10.4.": DNSServers.DRT,
  "10.6.": DNSServers.DRT,
  "10.60.": DNSServers.RTP,
  "10.64.": DNSServers.AMSTERDAM,
  "10.136.": DNSServers.BLR,
  "10.37.": DNSServers.PHX,
  "10.39.": DNSServers.PHX,
  "10.40.": DNSServers.PHX,
  "10.44.": DNSServers.PHX,
  "10.45.": DNSServers.PHX,
  "10.46.": DNSServers.PHX,
  "10.47.": DNSServers.PHX,
  "10.51.": DNSServers.PHX,
  "10.53.": DNSServers.PHX,
  "default": DNSServers.PHX,
  "nucloud_gcp": DNSServers.GCP
}

# Number of microseconds in a day. Used for entity metric queries.
USECS_IN_ONE_DAY = 24 * 60 * 60 * 1000 * 1000

PORT = 9086

PANACEA_CENTRAL_HOST = "10.48.64.122"
PANACEA_CENTRAL_PORT = 5002

class ResourceType:
  """
  Class for constants to represent resource types.
  """
  NOS_CLUSTER = "$NOS_CLUSTER"
  PRISM_CENTRAL = "$PRISM_CENTRAL"
  XI_PORTAL = "$XI_PORTAL"
  XI_INTERNET_GATEWAY = "$XI_INTERNET_GATEWAY"
  XI_TENANT = "$XI_TENANT"
  XI_INSIGHT = "$XI_INSIGHT"
  AVM = "$AVM"
  DCM = "$DCM"
  LOAD_BALANCER = "$LOAD_BALANCER"
  AGS_CLUSTER = "$AGS_CLUSTER"
  MX_ROUTER = "$MX_ROUTER"
  PA_GATEWAY = "$PA_GATEWAY"
  TWO_NODE_NOS_CLUSTER = "$TWO_NODE_NOS_CLUSTER"
  SINGLE_NODE_NOS_CLUSTER = "$SINGLE_NODE_NOS_CLUSTER"
  IAM_CLUSTER = "$IAM_CLUSTER"
  SELENIUM_VM = "$SELENIUM_VM"
  NUTANIX_CENTRAL = "$NUTANIX_CENTRAL"
  ARISTA_SWITCH = "$ARISTA_SWITCH"
  MCM = "$MCM"
  MCM_TENANT = "$MCM_TENANT"
  LTSS = "$LTSS"
  NC2 = "$NC2"
  NC2_TENANT = "$NC2_TENANT"
  NUCAS_CLUSTER = "$NUCAS_CLUSTER"
  KUBE_CLUSTER = "$KUBE_CLUSTER"

class Prometheus:
  """
  Class to represent constants related to Prometheus.
  """
  DEFAULT_PORT = 30900

class CPUArchitecture:
  """
  Class for constants to represent cpu architecture.
  """
  X86 = "x86"
  PPC = "ppc"

class BaseDiskType:
  """Base Class for Disk Type."""

class HDDType(BaseDiskType):
  """HDD Disk Type."""

class SSDType(BaseDiskType):
  """SSD Disk Type."""

class NVMeType(SSDType):
  """NVMe Disk Type."""

class CloudHibernateType(BaseDiskType):
  """Cloud Disk"""

class DiskType:
  """Class for constants to represent the type of disks.
  """
  HDD = HDDType
  SSD = SSDType
  NVMe = NVMeType
  CloudHibernate = CloudHibernateType

  @staticmethod
  def resolve(string):
    """Resolve the Disk Type using the string.

    Args:
      string (str): Disk type string.

    Returns:
      BaseDiskType

    Raises:
      NuTestError: If the Disk Type cannot be resolved using the string.
    """
    if string == "HDD":
      return HDDType
    # For SSDs, the string can be SSD-PCIe, SSD-SATA etc.
    if "SSD" in string:
      return SSDType
    if string == "NVMe":
      return NVMeType
    if "CLOUD-Hibernate-" in string:
      return CloudHibernateType
    raise ExpError("Unknown disk type: %s" % string,
                      )

POWERPC_MODELS = ["CS822", "CS821", "P8DTU", "powerpc"]

class KMSDetails:
  """
  Class for maintaining the external key management servers details.
  """

  DEFAULT_CSR_INFO = {
    "email": "QA@nutanix.com",
    "organization": "NTNX",
    "organizational-units": "QA,Sales",
    "country": "IN",
    "city": "Blr",
    "state": "KA"
  }

  # Location of the self signed cert on a CVM.
  SELF_SIGNED_CERT_LOCATION = "/home/nutanix/certs/svm.crt"

  # Script to get the certificates signed.
  CERTIFICATES_SIGN_SCRIPT = PackageHandler.get_resource_path(
    os.path.join('framework', 'entities', 'helpers',
                 'get_signed_certs.py'))

  # Default CA certificate information.
  NUTANIX_DEFAULT_CA_CERT_NAME = "nutanix_local_ca"
  NUTANIX_LOCAL_CA_CERT_LOCATION = PackageHandler.get_resource_path(
    os.path.join('framework', 'entities',
                 'nutanix_ca_certificate.crt'))

  # External Key Management Server IPs.
  KMS_SERVER_DETAILS = {
    'SAFENET' : {'IP' : '10.1.133.3',
                 'USERNAME' : 'admin',
                 'PASSWORD' : 'nutanix/4u',
                 'CA_CERT_NAME' : NUTANIX_DEFAULT_CA_CERT_NAME,
                 'CA_CERT' : NUTANIX_LOCAL_CA_CERT_LOCATION},
    'IBM' : {'IP' : '10.4.45.192',
             'USERNAME' : 'SKLMadmin',
             'PASSWORD' : 'Apple4u2$',
             'CA_CERT_NAME' : NUTANIX_DEFAULT_CA_CERT_NAME,
             'CA_CERT' : NUTANIX_LOCAL_CA_CERT_LOCATION}
  }

  DEFAULT_KMS_SERVER_DETAILS = KMS_SERVER_DETAILS['SAFENET']
  EPHEMERAL_KMS_IP = "10.40.121.198"
  EPHEMERAL_KMS_IP_2 = "10.40.239.23"
  PYKMIP_KMS_IP = "10.40.238.97"
  PYKMIP_KMS_NAME = "pykmip_kms"
  PYKMIP_CA_NAME = "pykmip_ca"
  AZURE_KMS_NAME = "azure"
  AZURE_KV_URL = "https://cloud-kms1.vault.azure.net"
  AZURE_TENANT_ID = "bb047546-786f-4de1-bd75-24e5b6f79043"
  AZURE_CLIENT_ID = "bd85ffc3-670f-4283-bc37-3491a7ee91ab"
  AZURE_CLIENT_SECRET = "Wk38Q~TvKMkGavzhmRvT75rruWav0R1yxmsjmb1l"
  AZURE_CLIENT_SECRET_2 = "cT_8Q~5OPjDetHnSZgmsdwHgta3szerMdaexdb-T"
  AZURE_KEY_NAME = "testkey1"
  AZURE_EXPIRY_DATE = "01/03/2026"
  AZURE_EXPIRY_DATE_2 = "07/01/2026"

CMD_LINE_RESOURCE_NAME = {
  ResourceType.NOS_CLUSTER: "NOS",
  ResourceType.PRISM_CENTRAL: "PC",
  ResourceType.XI_PORTAL: "XI",
  ResourceType.XI_INTERNET_GATEWAY: "XIG",
  ResourceType.AVM: "AVM",
  ResourceType.DCM: "DCM",
  ResourceType.LOAD_BALANCER: "LB",
  ResourceType.MX_ROUTER: "MX",
  ResourceType.PA_GATEWAY: "PA",
  ResourceType.AGS_CLUSTER: "AGS",
  ResourceType.TWO_NODE_NOS_CLUSTER: "2NODE",
  ResourceType.SINGLE_NODE_NOS_CLUSTER: "1NODE",
  ResourceType.IAM_CLUSTER: "IAM_CLUSTER",
  ResourceType.SELENIUM_VM: "SELENIUM",
  ResourceType.NUTANIX_CENTRAL: "NC",
  ResourceType.ARISTA_SWITCH: "ARISTA_SWITCH",
  ResourceType.MCM: "MCM",
  ResourceType.MCM_TENANT: "MCM_TENANT",
  ResourceType.LTSS : "LTSS",
  ResourceType.NC2: "NC2",
  ResourceType.NC2_TENANT: "NC2_TENANT",
  ResourceType.NUCAS_CLUSTER: "NUCAS",
  ResourceType.KUBE_CLUSTER: "KUBE"

}

CLASS_NAME_TO_RESOURCE_TYPE_MAP = {
  "NOSCluster": ResourceType.NOS_CLUSTER,
  "SingleNodeNOSCluster": ResourceType.SINGLE_NODE_NOS_CLUSTER,
  "TwoNodeNOSCluster": ResourceType.TWO_NODE_NOS_CLUSTER,
  "PrismCentralCluster": ResourceType.PRISM_CENTRAL,
  "NutanixCentral": ResourceType.NUTANIX_CENTRAL,
  "NucasCluster": ResourceType.NUCAS_CLUSTER
}

SIMULATED_PE_IP = "10.40.40.40"

# These are mostly set by testdriver for test reporting references.
TEST_DRIVER_ENV_VARS = {
  'NUTEST_BASE_URL',
  'NUTEST_BRANCH',
  'NUTEST_LOGDIR'
  'NUTEST_PATH',
  'NUTEST_WEB_PORT',
  'NUTEST_WEB_IP',
  'TEST_RESULT_URL'
}
NUTEST_ENV_VARS = {
  '_NUTEST_AUX_LOGGERS',
  '_NUTEST_PROFILE_FUNCTIONS',
  '_NUTEST_PROFILING',
  '_NUTEST_RUN_ID',
  'ASYNC_SSH',
  'COVERAGE_PROCESS_START',
  'IGNORE_CLUSTER_CAN_DESTROY',
  'INTERFACE_TYPE',
  'IPV6_INTERFACE',
  'JARVIS_PASSWORD',
  'JARVIS_USER',
  'JARVIS_WEBSERVICE_URL',
  'JITA_CLOUD_AGENT_RUN',
  'JITA_WEBSERVICE_URL',
  'NAMESPACED_VERSION',
  'NESTED_AHV',
  'NUCAS_AWS',
  'NUCLOUD_AWS',
  'NUCLOUD_AZURE',
  'NUCLOUD_DMZ',
  'NUCLOUD_GCP',
  'NUCLOUD_GCP_FILE_SERVER',
  'NUCLOUD_TESTER_LOCATION',
  'NUTEST_BASTION_HOST',
  'NUTEST_BASTION_HOST_PORT',
  'NUTEST_BASTION_HOST_USER',
  'NUTEST_CERT_PATH',
  'NUTEST_CLOUD_CONNECT_CLUSTER',
  'NUTEST_COLORED_LOGS',
  'NUTEST_DEV_MODE',
  'NUTEST_DISABLE_UTC_LOGGING',
  'NUTEST_HTTP_PC_DECORATOR_RETRIES',
  'NUTEST_HTTP_PC_RETRIES',
  'NUTEST_IDENTITY_FILE_PATH',
  'NUTEST_RSA_KEY_PATH',
  'NUTEST_SKIP_RESOURCE_CONNECT',
  'NUTEST_SSH_ROUTE',
  'NUTEST_SUDO_ENABLED',
  'NUTEST_TELEPORT_CLUSTER',
  'NUTEST_TELEPORT_BASTION_HOST',
  'NUTEST_UNSET_UTC',
  'PVT_KEY',
  'RDM_USER',
  'RDM_PASSWORD',
  'RESET_HOST_PWD',
  'SKIP_COLLECTORS',
  'USE_NTLM_TRANSPORT',
  'WINDOWS_SSH_USERNAME',
  'WINDOWS_SSH_PASSWORD'
}


SENSITIVE_FIELDS = {
  'user',
  'passwd',
  'hypervisor_username',
  'hypervisor_password',
  'ipmi_username',
  'ipmi_password',
  'ssh_key',
  'username',
  'password'
}

SENSITIVE_APIS = {
  'api/v1/clusters',
  'rest/v2.0/hosts',
  'api/v1/nodes'
}
