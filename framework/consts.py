"""
Copyright (c) 2015 Nutanix Inc. All rights reserved.

Author: digvija.dalapat@nutanix.com

TestLoader test.
"""

import os
import base64
import platform
# from framework.exceptions.driver_error import (
#   NuTestRunnerTimeoutError, NuTestInvalidTestOperationError,
#   NuTestResourceMismatchError)
# from framework.exceptions.interface_error import NuTestInterfaceError
from framework.vm_helpers.lib.package_handler import PackageHandler

# Client and loader param names
PYTHON_PATH = os.environ.get("PYTHONPATH")
DEFAULT_LOGS_DIR = os.path.join(PYTHON_PATH, "logs")
DEFAULT_TEST_DIR = os.path.join(PYTHON_PATH, "testcases")
BASE_CLASSES = ['NuTest', 'NOSTest', 'IAMTest']
ALLOWED_TEST_METHODS = [
  '__class__', '__delattr__', '__format__',
  '__getattribute__', '__hash__', '__init__', '__metaclass__',
  '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
  '__sizeof__', '__str__', '__subclasshook__', '__dir__', '__eq__', '__ge__',
  '__gt__', '__le__', '__lt__', '__ne__', '__init_subclass__',
  '_NOSTest__fetch_cluster_names', '_NOSTest__add_pre_post_runs',
  '_NOSTest__validate_expected_vs_specified_resources',
  '_NOSTest__validate_resources_from_json', '_NOSTest__validate_resource_spec',
  '_NOSTest__handle_resources', '_NOSTest__handle_clusters',
  '_NOSTest__get_resources', '_NOSTest__validate_resource_spec',
  '_NOSTest__create_resource_objects', '_NOSTest__load_clusters_from_json',
  'class_setup', 'class_teardown', 'setup', 'teardown', 'update',
  'register_callback', 'invoke_callback', 'update_expected_fatals',
  'set_param', 'get_param', 'delete_param', 'get_resource_by_name',
  'get_resources_by_type', 'get_resources_by_tag', '_NuTest__set_custom_data',
  '_NuTest__get_custom_data', '_NOSTest__handle_cluster_order',
  '_IAMTest__add_pre_post_runs', '_IAMTest__create_entity',
  '_IAMTest__create_factories', '_IAMTest__handle_clusters',
  '_IAMTest__create_resource_objects', '_IAMTest__get_resources',
  '_IAMTest__handle_resources',
  '_IAMTest__validate_expected_vs_specified_resources',
  '_IAMTest__validate_resource_spec', '_IAMTest__validate_resources_from_json',
  'get_pc_entity', 'get_pe_entity', 'get_pc_factories', 'get_pe_factories',
  'get_entity', 'get_factories', 'set_entity_factory_info'
]
NON_TEST_EXCEPTIONS = (
  ArithmeticError, AttributeError, ImportError,
  LookupError, NameError, UnboundLocalError,
  ReferenceError, NotImplementedError, KeyError,
  SyntaxError, TypeError, ValueError
)

#constants for the exit code - parent collects the exit code.
ABORT_EXIT_CODE = 99

#Non-Framework environment constants.
JARVIS_URL = "https://jarvis.eng.nutanix.com"
CANAVERAL_PYPI_SERVER_ADDR = ("canaveral-artifacts.corp.nutanix.com", 8090)
ARTIFACTORY_INDEX_PATH = \
"artifactory.dyn.ntnxdpro.com/artifactory/api/pypi/canaveral-legacy-pypi/simple"
SERVICE_USER = "svc.nutest"
SERVICE_USER_ARTIFACTORY_API_KEY = \
  "AKCp8k8iRQWTykQzVSwAGctddDBqdYZQ3VEGf55TVi9T1RUgecja8PSpSJUeZF35JN7zuMqKA"
ARTIFACTORY_HOST = "artifactory.dyn.ntnxdpro.com"

RDM_URL = "https://rdm.eng.nutanix.com"

#readonly=True/False
READONLY = False #default

# This should be set, tells whether a test is destructive or not.
# Should not leave it empty.

#ABORT_ON_FAILURE=True/False
ABORT_ON_FAILURE = False

# Constants for retrying.
MAX_RETRIES = 5
MAX_SLEEP_INTERVAL = 10

SAFE_SIZE_FOR_HTTP_BODY = 80 * 1024 # 80 KB. Upto 100 KB works.

# Delimiters for a class/test variation
TEST_VARIATIONS_DELIMITER = "___"
CLASS_VARIATIONS_DELIMITER = "~~~"

# JIRA authentication info
DEFAULT_JIRA_SERVER = "https://jira.nutanix.com"
DEFAULT_JIRA_USER = "svc.nutest.jira"
DEFAULT_JIRA_PASSWORD = base64.b64decode("bGxVelRSUW8h")
DEFAULT_JIRA_TOKEN = "NzY1NjIwMTk0Mjg4OqE5qJWp0JzqfzUZztUcPr2pqrHF"

# Template Paths.
# The path is to be specified by the user for
# composite resources with value - '$AUTO'
COMPOSITE_RESOURCE_TEMPLATE_PATHS = {
  '$MICRO_XI': PackageHandler.get_resource_path(os.path.join(
    'framework', 'config', 'resource_spec_templates', 'micro_xi.json')),
  '$TOPOLOGY': '$AUTO',
  '$TEMPLATE': '$AUTO'
}

NUTEST_INSTALLABLE_PACKAGES = [
  "nutest-stats",
  "nutest-docker",
]


#NUTEST SVC USER FOR JITA CALL
NUTEST_SVC_USER = "nutest.svc@nutanix.com"
NUTEST_SVC_PASSWORD = "ZnpNWkAyY2kqSCtteFNVeUROP2o=\n"

CREDENTIALS_FILE_PATH = \
  "http://endor.dyn.nutanix.com/GoldImages/vault/key_store.json"
if platform.system() == 'Darwin':
  DECRYPT_BINARY_PATH = \
    "http://endor.dyn.nutanix.com/GoldImages/vault/Mac/decrypt_data"
  DECRYPT_BINARY_FILER_VERSION_PATH = \
    "http://endor.dyn.nutanix.com/GoldImages/vault/Mac/tools_decrypt_version"
  LOCAL_DECRYPT_BINARY_PATH = "/Applications/decrypt_data"
  LOCAL_DECRYPT_BINARY_VERSION = "/Applications/tools_decrypt_version"
else:
  DECRYPT_BINARY_PATH = \
    "http://endor.dyn.nutanix.com/GoldImages/vault/linux/decrypt_data"
  LOCAL_DECRYPT_BINARY_PATH = os.path.join(PYTHON_PATH, "tmp", "decrypt_data")
