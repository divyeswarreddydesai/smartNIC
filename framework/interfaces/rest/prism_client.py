# Copyright (c) 2016 Nutanix Inc. All rights reserved.

# Author: ashrith.sheshan@nutanix.com
#         bharath.kalur@nutanix.com
"""Python module for initiating and executing commands via REST API.
"""
# pylint: disable = too-many-branches, import-outside-toplevel, no-name-in-module
# pylint: disable = too-many-statements, consider-merging-isinstance
# pylint: disable = too-many-locals, protected-access, arguments-differ
# pylint: disable = simplifiable-if-expression, no-else-return, broad-except
# pylint: disable = too-many-branches, no-else-continue
# nulint: disable=ImportsValidator

import copy
import json
import os
import random
import time
import traceback

import requests

from framework.entities.vm.pcvm import PCVM
from framework.exceptions.interface_error import (
  NuTestInterfaceError, NuTestHTTPError, NuTestInterfaceTransportError,
  NuTestPrismError, NuTestPrismDownError, NutestPrismEditConflictError,
  NuTestCommandExecutionError, NuTestClientAuthenticationError,
  NuTestClientForbiddenError)
from framework.exceptions.nutest_error import NuTestError
from framework.exceptions.nutest_value_error import NuTestValueError
from framework.interfaces.consts import PRISM_USER, PRISM_PASSWORD, \
  PRISM_DEFAULT_PASSWORD, PRISM_PORT, ADMIN_PRISM_USER, ADMIN_PRISM_PASSWORD
from framework.interfaces.http.http import HTTP, Session
from framework.lib.consts import ResourceType
from framework.lib.decorators import retry, handle_exception
from framework.lib.error_categorisation import ErrorCategory
from framework.lib.lock import lock_file
from framework.lib.nulog import INFO, DEBUG, WARN, ERROR
from framework.lib.utils import get_ip_type, get_resource_type, \
  get_prism_leader, fetch_jarvis_metadata


class PrismRestVersion:
  """
  Class to hold the constants representing the Prism Rest versions.
  """
  V0_8 = "v0.8"
  V1 = "v1"
  V2_0 = "v2.0"
  V3_0 = "v3.0"
  V4_0 = "v4.0"
  V4_0_B1 = "v4.0.b1"
  # Default is used for internal purposes, please refrain from using it.
  # If you want to imply default version, don't pass version.
  DEFAULT = "DEFAULT"

class PrismClient(HTTP):
  """Class for the REST API interface

  Examples:
  1. Using it with a Cluster object

      client = PrismClient(cluster=cluster)
      print client.get(url='/vms').json()

  2. Using it with a SVM object

      svm = SVM(ip='10.4.227.146')
      client = PrismClient(svm=svm)
      print client.get(url='/vms').json()

  3. Using extra optional parameters

      svm = SVM(ip='10.4.227.146')
      client = PrismClient(svm=svm, username='admin', password='nutanix/4u',
                           port=9440, base_uri='https://x.x.x.x:9440/
                           PrismGateway/services/rest/v1')
      print client.get(url='/vms').json()

  4. Posting a JSON data using a specific API version

      client = PrismClient(svm=svm, version='v3')
      print client.post(url='/networks/list', json={"kind": "network"}).json()
  """

  PRISM_LOGIN_PATH = 'PrismGateway/j_spring_security_check'
  VERSION_BASE_PATH = {
    PrismRestVersion.V0_8: 'api/nutanix/v0.8',
    PrismRestVersion.V1: 'PrismGateway/services/rest/v1',
    PrismRestVersion.V2_0: 'PrismGateway/services/rest/v2.0',
    PrismRestVersion.V3_0: 'api/nutanix/v3',
    PrismRestVersion.V4_0: '/api/prism/v4.0.b1/config'
  }

  DEFAULT_VERSION = PrismRestVersion.V0_8

  HEADERS_NAME = "headers"
  AUTHORIZATION_HEADER_KEY = "Authorization"
  DATA_NAME = "data"
  CERT = "cert"

  HEADERS_VALUE = {
    'content-type': 'application/json;charset=UTF-8',
    'Accept': 'application/json, text/javascript, */*; q=0.01'
  }

  IGNORED_PARAMS_LIST = ["data", "json", "debug", "verify", "headers",
                         "timeout", "cookies", "files", "auth",
                         "allow_redirects", "proxies", "hooks", "stream",
                         "cert"]

  RETRIABLE_500ERROR_RESPONSE = [b"Closed by peer", b"Connection was refused",
                                 b"Failed to persist the cookie",
                                 b"the database system is starting up",
                                 b"connection refused",
                                 b"Error encountered accessing Prism " \
                                   b"adapter, retry requested",
                                 b"Login error",
                                 b"failed to connect: LDAP Result Code 200"]

  def __init__(self, cluster=None, svm=None, version=DEFAULT_VERSION,
               username=None, password=None, port=PRISM_PORT, namespace=None,
               module="default", user_agent="Nutest-Framework", **kwargs):
    """This class defines methods to invoke REST calls.
    Accepts either a Cluster or SVM object

    Args:
      cluster(Cluster): Cluster object.
      svm (SVM): SVM object.
      version (str, optional): Version of Prism REST to be used.
      username(str, optional): Username to be used for authentication.
        Default: 'admin'.
      password(str, optional): Password to be used for authentication.
        Default: 'nutanix/4u'.
      port(int, optional): Port to connect for sending REST calls.
                          Defaults to 9440.
      namespace(str, optional): Namespace to which the endpoints belong
      module(str, optional): Module to which the url in a certain namespace
                             belongs. Defaults to "default".
      user_agent(str,optional): User-Agent by default would be set to
      'Nutest-Framework'

        NOTE: For xi portal, username and password should be
          passed mandatorily (Defaults will not be applicable in case
          of xi portal)

    Raises:
      NuTestValueError: Invalid params. (Cluster or SVM not passed)
    """
    from framework.entities.cluster.base_cluster import BaseCluster
    from framework.entities.cluster.xi_internet_gateway import \
      XiInternetGateway
    from framework.entities.cluster.xig_tenant_end_point import \
      XIGTenantEndPoint
    from framework.entities.vm.nos_vm import NOSVM

    if cluster:
      if isinstance(cluster, PCVM):
        self._svm = cluster
      elif isinstance(cluster, XiInternetGateway) or \
              isinstance(cluster, XIGTenantEndPoint):
        # If rest_endpoint has IPv6 IP, it has to follow [<IP>]:<port> format
        self._cluster = cluster
        self._host = cluster.rest_endpoint
      elif cluster.resource_type == ResourceType.PRISM_CENTRAL:
        self._cluster = cluster
        ip = _bracket_enclose_if_ipv6(cluster.cluster_identifier)
        self._host = "{}:{}".format(ip, port)
      elif isinstance(cluster, BaseCluster):
        self._cluster = cluster
      else:
        raise NuTestValueError("Cluster object Expected. Passed: %s"
                               % str(cluster), category=ErrorCategory.USAGE)
    elif svm:
      if not isinstance(svm, NOSVM):
        raise NuTestValueError("NOSVM object Expected. But Passed:%s" %
                               str(svm), category=ErrorCategory.USAGE)
      self._svm = svm
    else:
      raise NuTestValueError("Either of SVM of Cluster objects are mandatory.",
                             category=ErrorCategory.USAGE)

    self.namespace = namespace
    self.module = module
    self.version = version

    self._secured_cluster = False

    if (cluster and not isinstance(cluster, PCVM) and hasattr(cluster, 'svms')
        and hasattr(cluster.svms[0], '_secure_prism_username')):
      # check for hasattr(cluster, svms) is in case for XI resources.
      self._username = cluster.svms[0]._secure_prism_username
      self._secured_cluster = True
    elif svm and hasattr(svm, '_secure_prism_username'):
      self._username = svm._secure_prism_username
      self._secured_cluster = True
    elif username:
      self._username = username
    else:
      self._username = PRISM_USER

    if (cluster and not isinstance(cluster, PCVM) and hasattr(cluster, 'svms')
        and hasattr(cluster.svms[0], '_secure_prism_password')):
      self._password = cluster.svms[0]._secure_prism_password
    elif svm and hasattr(svm, '_secure_prism_password'):
      self._password = svm._secure_prism_password
    elif password:
      self._password = password
    else:
      if self._username == ADMIN_PRISM_USER:
        self._password = ADMIN_PRISM_PASSWORD
      else:
        self._password = PRISM_PASSWORD

    self._port = port
    self._id_token = None
    self._iam_token = None
    self._user_agent = os.environ.get("USER-AGENT", user_agent)
    super(PrismClient, self).__init__(**kwargs)

    # For XI_PC/XI_TENANT, they must have unique tenant credentials.
    # Default credentials should not be used for them unlike PE/PC.
    # Each instance will be holding their unique credentials.
    if cluster and hasattr(cluster, 'resource_type'):
      if (cluster.resource_type in [ResourceType.XI_PORTAL,
                                    ResourceType.XI_INTERNET_GATEWAY]
          or (cluster.resource_type == ResourceType.XI_TENANT and
              not cluster.is_admin)
          or (cluster.resource_type == ResourceType.PRISM_CENTRAL and
              cluster.is_xi_pc)):
        if not username:
          self._username = self._cluster.prism_username
          self._password = self._cluster.prism_password
        if cluster.resource_type == ResourceType.XI_TENANT \
          and cluster.default_client_service_account:
          self._default_client_service_account = \
              cluster.default_client_service_account
          self._iam_token = True
        else:
          self.set_bearer_header_for_xi()
          self._id_token = True

  @property
  def password(self):
    """
    Returns the password of the client instance.

    Returns:
      str: The password of the client instance.
    """
    return self._password

  @property
  def server_object(self):
    """
    Returns the server object wrapped by this client. That would be the value of
    self._cluster, if it exists. Otherwise, it would be the value of self._svm.

    Returns:
      object
    """
    if hasattr(self, "_cluster"):
      return self._cluster
    else:
      return self._svm

  @property
  def port(self):
    """
    Returns the port of the client instance.

    Returns:
      str: The port of the client instance.
    """
    return self._port

  @property
  def username(self):
    """
    Returns the username of the client instance.

    Returns:
      str: The username of the client instance.
    """
    return self._username

  @property
  def prism_password_lock_file(self):
    """
    Find a unique name to track for the lock file. The lock file name should
    be tied to the cluster level since that is where the password modifications
    are performed. The approach here is to use the cluster name for the unique
    aspect of the lock file name. If the cluster name can't be found, then
    we'll fall back to using a static string. With a long timeout for the lock
    acquisition we should be able to ride over any lock contention if multiple
    objects use the same lock file name.

    Once the prism_password_lock_file is set it doesn't change for the lifetime
    of the object.

    Returns:
      str: The lock file to be used when performing prism password changes.
    """
    if hasattr(self, '_prism_password_lock_file'):
      return self._prism_password_lock_file

    lock_suffix = "NUTEST_DEFAULT_LOCK_NAME"
    try:
      if hasattr(self, '_cluster') and hasattr(self._cluster, 'name'):
        lock_suffix = self._cluster.name
      elif hasattr(self, '_svm'):
        cluster_uuid = self._svm.cluster_uuid
        lock_suffix = str(cluster_uuid) if cluster_uuid else lock_suffix
    except Exception:
      WARN("Unable to find cluster name for lock file name, using default: {}"
           .format(traceback.format_exc()))

    lock_file_name = "prism_password_lock_{}".format(lock_suffix)
    self.prism_password_lock_file = lock_file_name
    return self._prism_password_lock_file

  @prism_password_lock_file.setter
  def prism_password_lock_file(self, lock_file_name):
    """
    Sets the prism password lock file name.
    Args:
      lock_file_name(str): Lock file name.
    Raises:
      NuTestError: If the lock file name is changed after being set.
    """
    # We should disallow changing the prism password lock file name once set.
    if getattr(self, '_prism_password_lock_file', None):
      raise NuTestError("Blocking modification of existing "
                        "prism_password_lock_file to {}"
                        .format(lock_file_name))
    DEBUG("Setting prism_client prism_password_lock_file to {}"
          .format(lock_file_name))
    self._prism_password_lock_file = lock_file_name

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def change_default_password(self, new_password, retries=1,
                              validate_default_password=False):
    """This method reset the password from default password(Nutanix/4u)
        to given password.

    Args:
      new_password (str): new password to be set.
      retries (int): Number of retries to change the password.
        Default is 1.
        NOTE : Retrying more times might lock the password as there
        would be invalid login attempts.
      validate_default_password (bool): raises exception when
        password is not default.

    Returns:
      None

    Raises:
      NuTestInterfaceError: If unable to change password.
    """
    if new_password == PRISM_DEFAULT_PASSWORD:
      WARN("Given password is default password, hence skipping the default "
           "password change")
      return

    if not self.check_auth_with_password():
      if validate_default_password:
        raise NuTestClientAuthenticationError("password is not default")
      WARN("Password has already been changed from the default password, "
           "hence skipping the default password change")
      return

    self.__change_password_and_check(new_password, retries)

    # Accept EULA.
    INFO("Accepting EULA")
    url = "eulas/accept"
    accept_eula_url = self.__get_absolute_url(url,
                                              version=PrismRestVersion.V1)
    data = {"username": "Nutanix", "companyName": "Nutanix",
            "jobTitle": "MTS"}
    session = Session()
    response = session.post(url=accept_eula_url,
                            data=json.dumps(data),
                            auth=(PRISM_USER, new_password),
                            headers=self.HEADERS_VALUE, verify=False)
    if not response.ok:
      WARN("Unable to Accept EULA: %s" % response.content)

    if hasattr(self, '_cluster') and self._cluster.is_nested_ahv:
      INFO("Disabling Pulse explicitly on Nested AHV cluster")
      self._cluster.update_pulse(False)
      return
    elif hasattr(self, '_svm'):
      response_ = self._send(method="get", url="hosts",
                             version=PrismRestVersion.V2_0)
      if (response_.get('entities') and
          response_['entities'][0]['block_model_name'] == "NestedAHV"):
        INFO("Disabling Pulse explicitly on Nested AHV cluster")
        self.send(method="put", url="pulse", version=PrismRestVersion.V1,
                  json={"enable": False})
        return

    # Enable Pulse.
    INFO("Enabling Pulse")
    url = "pulse"
    pulse_url = self.__get_absolute_url(url, version=PrismRestVersion.V1)
    data = {"emailContactList": ['no-email@nutanix.com'], "enable": True,
            "verbosityType": None,
            "enableDefaultNutanixEmail": False, "defaultNutanixEmail": None,
            "nosVersion": None, "isPulsePromptNeeded": False,
            "remindLater": None}
    response = session.put(url=pulse_url,
                           data=json.dumps(data),
                           auth=(PRISM_USER, new_password),
                           headers=self.HEADERS_VALUE, verify=False)
    if not response.ok:
      WARN("Failed to enable Pulse: %s" % response.content)

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def reset_and_change_default_password(self, new_password=PRISM_PASSWORD):
    """This method reset the password to given password.
    Args:
      new_password (str): new password to be set.

    Returns:
      None

    Raises:
      NuTestInterfaceError: If unable to change password.
    """
    DEBUG("Resetting password to default {0} before attempting "
          "change_default_password, to ensure the admin password is {0}"
          .format(PRISM_DEFAULT_PASSWORD))
    svm = get_prism_leader(self._svm) if hasattr(self, '_svm') else \
      self._cluster.prism_leader
    svm.execute(cmd="reset_admin_password.py")

    # Sleeping until state sync across SVMs.
    DEBUG("Sleeping 60s after pwd reset to wait for pwd sync")
    time.sleep(60)
    DEBUG("Changing default admin password to: '{}'"
          .format(self.log_password(new_password)))
    self.change_default_password(new_password)

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.DATAPARSE)
  def get_params(self, **kwargs):
    """Getting the params from kwargs.

      Returns:
        (Tuple): params and the remaining kwargs.
      """
    params = dict((key, value) for key, value in kwargs.items() if key
                  not in self.IGNORED_PARAMS_LIST)
    args = dict((key, value) for key, value in kwargs.items() if key not in
                list(params.keys()))

    return params, args

  @retry(retries=20,
         sleep_interval=15,
         exception_list=[NuTestHTTPError,
                         requests.exceptions.ChunkedEncodingError])
  def wait_for_prism_gateway_services(self, ignore_errors=False, **kwargs):
    """Waits for the Prism Gateway services are up on the cluster/SVM.

    Args:
      ignore_errors(bool): If specified True, will ignore the exceptions
        thrown from HTTP.

    Kwargs:
      retries(int, optional): Number of retries. Default is 10.
      retry_interval(int, optional): Retry interval in secs. Default is 30.

    Raises:
      NuTestHTTPError: Raised when failed to get the response for the
        gateway services.
    """
    http = HTTP(retries=kwargs.get('retries', 10),
                retry_interval=kwargs.get('retry_interval', 30),
                timeout=kwargs.get('timeout', 180))
    urls = []
    if hasattr(self, '_svm'):
      svm_ip = _bracket_enclose_if_ipv6(self._svm.ip)
      urls.append('https://%s:%s/PrismGateway/services/rest/v1/heartbeat' % (
        svm_ip, self._port))
    else:
      svm_ips = [_bracket_enclose_if_ipv6(svm.ip) for svm in self._cluster.svms]
      for svm_ip in svm_ips:
        urls.append('https://%s:%s/PrismGateway/services/rest/v1/heartbeat'% (
          svm_ip, self._port))

    for url in urls:
      try:
        http.get(url)
        INFO("Prism gateway services are up.")
      except NuTestHTTPError as err:
        if ignore_errors:
          # Try on next URL
          WARN("Ignoring the errors while getting the response from %s" % url)
          break
        WARN("Exception while trying to connect to prism gateway: %s"
             % str(err))
        err.category = ErrorCategory.RESOURCE_STATE
        raise err

  def set_bearer_header_for_xi(self):
    """For Xi, Update session header with token/Cookie
    """
    self._session.headers.update(self._cluster.get_header_for_xi())

  def set_iam_token_in_header(self, url):
    """Method for setting IAM token in header.

    Args:
      url(str): URL to access using IAM token.
    """
    self._session.headers.update\
      (self._default_client_service_account.get_session_header(url=url))

  def set_token_in_header(self, token_info, use_existing=True):
    """Update session header with a bearer token.

    Args:
      token_info(dict): Attributes needed to generate a particular token.
      use_existing(bool): True, if existing token can be reused. False, if new
                          token need to be generated (on expiry). Default: True
    """
    token = self._cluster.get_token(token_info, use_existing)
    headers = {"content-type": "application/json",
               "Authorization": "Bearer %s" % token}
    self._session.headers.update(headers)

  def log_password(self, password):
    """
    Args:
      password (str): Password to maybe log.
    Returns:
      str: Password to log.
    """
    return password if not self._secured_cluster else "*" * 6

  def unlock_prism_account(self):
    """
    Method to unlock the prism account.
    Prism account gets locked when multiple login attempts are made with invalid
    credentials.
    Unlock command will be executed on all SVMs of the cluster.
    If this method returns successfully, the password will be set to the
    same password as was prior to unlocking.

    Returns:
      None

    Raises:
      NuTestPrismError: When failed to execute account unlock command on SVM.
                        When unlock operation is not successful.
    """
    INFO("Unlocking Prism account")
    from framework.entities.cluster.base_cluster import BaseCluster

    if hasattr(self, '_cluster') and isinstance(self._cluster, BaseCluster):
      svms = self._cluster.svms
    else:
      from framework.entities.vm.nos_vm import NOSVM
      svms = [NOSVM(svm_ip) for svm_ip in
              self._svm.execute("svmips")['stdout'].split()]

    for svm in svms:
      try:
        svm.execute("sudo faillock --user admin --reset")
      except NuTestCommandExecutionError as exc:
        raise NuTestPrismError("Failed while executing command to unlock "
                               "prism account: %s" % exc)

    # Sleeping until state sync across SVMs.
    DEBUG("Sleeping 60s to wait for password sync")
    time.sleep(60)

    # On reset, it is setback to last password before locking.
    # This can be either default/admin password based on the state.
    # Hence validating with both and resetting it to admin password finally.
    password = (self.password if self._secured_cluster
                else ADMIN_PRISM_PASSWORD)
    DEBUG("After unlock, verifying if admin user password "
          "is still default password ({})".format(PRISM_DEFAULT_PASSWORD))
    if self.check_auth_with_password():
      DEBUG("After unlock, admin user password is still default password, "
            "resetting it to '{}'".format(self.log_password(password)))
      self.change_default_password(password)

    DEBUG("Verifying if the password is set to '{}'"
          .format(self.log_password(password)))
    password_correct = self.check_auth_with_password(password)

    if not password_correct:
      raise NuTestPrismError(
        "Password check failed with both '{}' and '{}' for admin user after "
        "unlock".format(PRISM_DEFAULT_PASSWORD, self.log_password(password)))

    DEBUG("Prism admin user is unlocked successfully and set "
          "to '{}'".format(self.log_password(password)))

  def unlock_prism_account_without_passwd_change(self):
    """
    Method to only unlock the prism account.
    Prism account gets locked when multiple login attempts are made with invalid
    credentials.
    Unlock command will be executed only on one of the SVMs of the cluster.

    Returns:
      None

    Raises:
      NuTestPrismError: When failed to execute account unlock command on SVM.
                        When unlock operation is not successful.
    """
    INFO("Unlocking Prism account")
    from framework.entities.cluster.base_cluster import BaseCluster

    if hasattr(self, '_cluster') and isinstance(self._cluster, BaseCluster):
      svms = self._cluster.svms
    else:
      from framework.entities.vm.nos_vm import NOSVM
      svms = [NOSVM(svm_ip) for svm_ip in
              self._svm.execute("svmips")['stdout'].split()]

    try:
      svms[0].execute("sudo faillock --user admin --reset")
    except NuTestCommandExecutionError as exc:
      raise NuTestPrismError("Failed while executing command to unlock "
                             "prism account: %s" % exc)

    # Sleeping until state sync across SVMs.
    DEBUG("Sleeping 60s to wait for password sync")
    time.sleep(60)

    DEBUG("Prism admin user is unlocked successfully")

  @handle_exception(exception_type=NuTestError,
                    category_type=ErrorCategory.INTERFACE)
  def regenerate_token(self, token_info, url):
    """
    Regenerating Bearer token
    Args:
      token_info(dict): Attributes needed to generate a particular token.
      url(str): Absolute URL for the request.
    """
    if token_info:
      self.set_token_in_header(token_info, use_existing=False)
    elif self._id_token:
      self.set_bearer_header_for_xi()
    elif self._iam_token:
      self.set_iam_token_in_header(url)

  @retry(exception_list=[NuTestInterfaceTransportError, NuTestPrismDownError],
         retries=3, custom_decorator_retries='NUTEST_HTTP_PC_DECORATOR_RETRIES')
  def send(self, method, url, **kwargs):
    """Overriding the _send of http to manipulate the relative url part.

    Args:
      method (str): HTTP method.
      url (str): relative_url
      kwargs:
        retries (int): The retry count that has to be sent to HTTP's _send.
        include_header_resp (bool): Boolean to represent whether to return
          response along with header or not.
        base_path(str): Base URL path for forming URL.

    Returns:
      dict: The response content loaded as a JSON.

    Raises:
      NuTestPrismError: On Prism returning error codes in the response.
      NuTestInterfaceError: On failure to connect to server or
        if Prism Services are down on server.
    """
    namespace = kwargs.pop('namespace', self.namespace)
    module = kwargs.pop('module', self.module)
    version = kwargs.pop('version', self.version)
    token_info = kwargs.pop('token_info', None)
    base_path = kwargs.pop('base_path', None)
    kwargs.pop('set_default_password', True)
    idempotence_id = kwargs.pop('idempotence_id', None)
    ntnx_request_id = kwargs.pop('ntnx_request_id', None)
    etag = kwargs.pop('etag', None)

    if os.environ.get("NUTEST_HTTP_PC_RETRIES") and \
        int(os.environ.get("NUTEST_HTTP_PC_RETRIES")):
      # not assigning when NUTEST_HTTP_PC_RETRIES is 0
      # to make atleast one attempt.
      kwargs["retries"] = int(os.environ.get("NUTEST_HTTP_PC_RETRIES"))

    url = self.__get_absolute_url(url, version, namespace, module, base_path)

    if self._id_token is not None:
      kwargs[self.HEADERS_NAME] = kwargs.get(self.HEADERS_NAME,
                                             self._session.headers)
    elif token_info:
      self.set_token_in_header(token_info)
      kwargs[self.HEADERS_NAME] = kwargs.get(self.HEADERS_NAME,
                                             self._session.headers)
    elif self._iam_token:
      self.set_iam_token_in_header(url)
      kwargs[self.HEADERS_NAME] = kwargs.get(self.HEADERS_NAME,
                                             self._session.headers)
    else:
      headers_value = copy.deepcopy(self.HEADERS_VALUE)
      kwargs[self.HEADERS_NAME] = kwargs.get(self.HEADERS_NAME,
                                             headers_value)

    if not (kwargs[self.HEADERS_NAME].get(self.AUTHORIZATION_HEADER_KEY) or
            self.CERT in kwargs):
      self._session.auth = (self._username, self._password)

    # The 'Ntnx-Idempotence-Identifier' attribute to accept the uuid for the
    # task for any V4 API operations. V4 API accept the task_id to be
    # generated in the Header section and it will be accepted in
    # "Ntnx-Idempotence-Identifier". Ref: ENG-314504, ENG-366004.
    if idempotence_id:
      kwargs[self.HEADERS_NAME]['Ntnx-Idempotence-Identifier'] = \
        idempotence_id
    if self._user_agent:
      kwargs[self.HEADERS_NAME]['User-Agent'] = self._user_agent
    if etag or etag == "":
      kwargs[self.HEADERS_NAME]['If-Match'] = etag
    if ntnx_request_id:
      kwargs[self.HEADERS_NAME]['NTNX-Request-Id'] = ntnx_request_id
    elif ntnx_request_id == "":
      #When a user wants to send an empty NTNX-Request-Id,can give id as "".
      #This is required when we need to verify the api response with empty,
      #NTNX-Request-Id , empty id will return IDEMPOTENCY error api response.
      kwargs[self.HEADERS_NAME]['NTNX-Request-Id'] = ntnx_request_id

    if 'json' in kwargs:
      kwargs['data'] = json.dumps(kwargs.pop('json'))
      content_dict = {'content-type': 'application/json'}
      kwargs.setdefault('headers', {})
      if 'content-type' not in kwargs:
        kwargs['headers'].update(content_dict)

    include_header_resp = kwargs.pop("include_header_resp", False)
    try:
      return self._get_response_content(
        super(PrismClient, self)._send(method, url, **kwargs),
        include_header_resp)

    except NuTestHTTPError as exc:
      if exc.response.status_code == 401:
        if not self._id_token:
          _raise_nutest_prism_error(method, url, exc,
                                    NuTestClientAuthenticationError)

        elif any([token_info, self._id_token, self._iam_token]):
          return self.handle_bearer_token_auth_failure(
            method, url, token_info, include_header_resp, **kwargs)

      elif exc.response.status_code == 403:
        if any([token_info, self._id_token, self._iam_token]):
          return self.handle_bearer_token_auth_failure(
            method, url, token_info, include_header_resp, **kwargs)
        else:
          _raise_nutest_prism_error(method, url, exc,
                                    NuTestClientForbiddenError)
      elif exc.response.status_code == 409:
        raise NutestPrismEditConflictError(
          "CAS_MISMATCH/CONCURRENT_REQUESTS_NOT_ALLOWED",
          response=exc.response)
      elif exc.response.status_code in (503, 502):
        try:
          msg = json.loads(exc.response.content)["data"]["error"][0]["message"]
        except Exception:
          msg = exc.response.content
        raise NuTestPrismDownError(msg,
                                   response=exc.response,
                                   category=ErrorCategory.RESOURCE_STATE)
      # Added to accomodate retry on aplos server crash for memory
      # issues caused due to cgroup changes ENG-256246
      elif exc.response.status_code == 500 and \
        any(error_text in exc.response.content for error_text
            in self.RETRIABLE_500ERROR_RESPONSE):
        INFO("Sleeping 30s after getting 500 error before retrying")
        time.sleep(30)
        raise NuTestPrismDownError("Server might be down",
                                   response=exc.response,
                                   category=ErrorCategory.RESOURCE_STATE)
      else:
        _raise_nutest_prism_error(method, url, exc)

  # For backward compatibility.
  _send = send

  def handle_bearer_token_auth_failure(self, method, url, token_info,
                                       include_header_resp, **kwargs):
    """
    Regenerate the token and retry the request.
    Args:
      method (str): HTTP method.
      url (str): relative_url
      token_info (dict): Token information.
      include_header_resp (bool): Boolean to represent whether to return
        response along with header or not.
    Returns:
      dict: The response content loaded as a JSON.
    """
    # Try updating the bearer token in header.
    DEBUG("Authentication Failed. Trying to update token")
    self.regenerate_token(token_info, url)
    DEBUG("Retrying request after updating token")
    try:
      return self._get_response_content(
        super(PrismClient, self)._send(method, url, **kwargs),
        include_header_resp)
    except NuTestHTTPError as exc:
      _raise_nutest_prism_error(method, url, exc)

  def handle_password_auth_failure(self, method, url, set_default_password,
                                   include_header_resp, exception, **kwargs):
    """
    Reset the password and retry the request.
    Args:
      method (str): HTTP method.
      url (str): relative_url
      set_default_password (bool): If we should set the default password.
      include_header_resp (bool): Boolean to represent whether to return
        response along with header or not.
      exception (Exception): The exception from the calling method in case we
        need to raise earlier prior to doing any password modifications.
    Returns:
      dict: The response content loaded as a JSON.
    """
    # Give a 30min timeout for lock acquisition just in case there is some
    # lock contention we don't anticipate.
    with lock_file(self.prism_password_lock_file, timeout=2700, debug=True):
      if not set_default_password:
        _raise_nutest_prism_error(method, url, exception,
                                  NuTestClientAuthenticationError)
      if self.username != ADMIN_PRISM_USER:
        _raise_nutest_prism_error(method, url, exception,
                                  NuTestClientAuthenticationError)
      # Since we've grabbed the password operation lock we should check to see
      # if the password still fails. This handles the case of two threads
      # hitting a password auth failure and T1 grabs the lock and resets the
      # password.
      # T2 is waiting on the lock, thinking it should reset the password.
      # When it grabs the lock it shouldn't reset the password again, rather it
      # should check if the current password works. If it does, just return
      # without changing anything.
      try:
        return self._get_response_content(
          super(PrismClient, self)._send(method, url, **kwargs),
          include_header_resp)
      except NuTestHTTPError as exc:
        DEBUG("Request still fails, possibly performing password operations")
        exception = exc

      prism_password_fixed = False
      new_password = (self.password if self._secured_cluster
                      else ADMIN_PRISM_PASSWORD)
      if b"Account locked for user admin" in exception.response.content:
        # More than 5 attempts with invalid login creds, locks the account.
        # Unlocking it to handle parallel deployment on base cluster.
        self.unlock_prism_account()
        prism_password_fixed = True
      elif b"Password has expired" in exception.response.content:
        # Password expires after 60 days, reset from CLI if it does.
        if self.__is_nested_base_cluster():
          raise NuTestError("Password expired on nested base cluster")
        DEBUG("Resetting expired password to default")
        self.reset_and_change_default_password(new_password)
        prism_password_fixed = True
      if not prism_password_fixed:
        self.change_default_password(new_password)

    DEBUG("Retrying request after fixing the Prism password")
    try:
      return self._get_response_content(
        super(PrismClient, self)._send(method, url, **kwargs),
        include_header_resp)
    except NuTestHTTPError as exc:
      DEBUG("Request still fails after changing prism password")
      _raise_nutest_prism_error(method, url, exc)

  def check_auth_with_password(self, password=PRISM_DEFAULT_PASSWORD):
    """Check if Prism gets authenticated with default password.

    Args:
      password(str): password for which authentication has to be
      validated against.
        Default : PRISM_DEFAULT_PASSWORD

    Returns:
      bool: True if Prism auth is successful with default prism password.
      False otherwise.

    Raises:
      NuTestPrismDownError: If request to Prism service fails
                            even after retries.
    """
    sleep_interval = 30
    retries = 6
    while retries > 0:
      retries -= 1
      svm = (self._svm if hasattr(self, '_svm')
             else self._cluster.get_accessible_svm())
      url = "https://%s:9440/api/nutanix/v3/versions" % svm.ip
      try:
        if password == PRISM_DEFAULT_PASSWORD:
          log_password = PRISM_DEFAULT_PASSWORD
        else:
          log_password = ADMIN_PRISM_PASSWORD if \
            not self._secured_cluster else "*" * 6
        DEBUG("Executing sample REST API to test whether Prism authenticates "
              "for {} with {}".format(PRISM_USER, log_password))
        response = Session().get(
          url=url, auth=(PRISM_USER, password), verify=False)
        DEBUG("Status code for %s with %s : %s" %
              (PRISM_USER, log_password, response.status_code))
      except Exception as exc:
        ERROR("Failed while checking for %s with %s : %s" %
              (PRISM_USER, log_password, str(exc)))
        return False
      if response.status_code in (503, 502):
        if retries == 0:
          ERROR("All retries exhausted. Prism services on %s are still down."
                " Response code %s" % (svm.ip, response.status_code))
          raise NuTestPrismDownError("Prism Server %s might be down"
                                     % svm.ip,
                                     response=response,
                                     category=ErrorCategory.RESOURCE_STATE)
        DEBUG('Prism services are down on an SVM. '
              'Retrying in %s secs. Response code %s' %
              (sleep_interval, response.status_code))
        time.sleep(sleep_interval)
        continue
      else:
        break
    return True if response.ok else False


  @staticmethod
  def _get_response_content(response, include_header_resp=False):
    """Returns response content in a readable JSON format
    Args:
      response(requests.response): response object
      include_header_resp (bool): Whether to include header in the response or
        not.

    Returns:
      dict: The response content loaded as a JSON.
    """
    if include_header_resp:
      return response

    if response.status_code == 204:
      # Ensuring task pass but no content in response is handled
      return {"task_message": "Action Successful. No Content"}
    else:
      try:
        return json.loads(response.content)
      except (ValueError, TypeError):
        return response.content

  def _get_accessible_url(self):
    """Gets the accessible cluster/svm ip address for trying REST cmd

    Returns:
      str: url in this format https://<svm_ip>:port

    Raises:
      NuTestInterfaceError : Failed to find an SVM with Prism gateway up
                             and running on the cluster.
    """
    http = HTTP()
    urls = []
    if hasattr(self, '_svm'):
      svm_ip = _bracket_enclose_if_ipv6(self._svm.ip)
      urls.append('https://%s:%s' % (svm_ip, self._port))
    else:
      svm_ips = self._cluster.svm_ips_v6 if (
        os.environ.get('IPV6_INTERFACE') == "1") else self._cluster.svm_ips
      for svm_ip in svm_ips:
        if svm_ip in self._cluster.get_ignored_svm_ips():
          INFO("SVM IP: %s is ignored, "
               "continuing with another SVM IP" % svm_ip)
          continue

        svm_ip = _bracket_enclose_if_ipv6(svm_ip)
        url = 'https://%s:%s' % (svm_ip, self._port)
        urls.append(url)

    # shuffling so that if prism is down on a CVM we choose another first
    # in the next try.
    random.shuffle(urls)
    for url in urls:
      try:
        result = http.head(url, verify=False, retries=3, retry_interval=5,
                           retry_on_auth_failures=True, debug=False)
        if result.ok:
          return url
      except (NuTestInterfaceTransportError, NuTestHTTPError) as exc:
        WARN("Could not reach %s due to %s. Checking other urls."
             % (url, str(exc)))

    raise NuTestInterfaceError("Unable to connect SVM due to Prism failure "
                               "or Services down. Please check the logs.",
                               category=ErrorCategory.RESOURCE_STATE)

  def _is_cmsp_pc(self):
    """Checks if it's a CMSP enabled PC.

    Returns: True if CMSP enabled PC. False otherwise.
    """
    svm = (self._svm if hasattr(self, '_svm')
           else self._cluster.get_accessible_svm())
    if get_resource_type(svm.ip) != ResourceType.PRISM_CENTRAL:
      return False

    try:
      url = ("https://%s:9440/api/iam/authn/.well-known/openid-configuration"
             % svm.ip)
      resp = HTTP().get(url)
      return bool(resp.ok)
    except Exception as exc:
      ERROR("Failed while determining whether PC is CMSP enabled: %s" %str(exc))
      return False

  @retry(exception_list=[NuTestClientAuthenticationError], retries=3,
         sleep_interval=10)
  def _reset_passwd_in_msp_pc(self, new_password):
    """
    Resets password on CMSP enabled PC.

    Args:
      new_password(str): Password to be set to.

    Returns:
      bool: True, when password reset succeeds.

    Raises:
      NuTestError: When MSP is not running on the cluster.
      NuTestClientAuthenticationError: When failed to reset password.
    """
    try:
      url = self.__get_absolute_url(
        "users/password", base_path="api/iam/authn/v1")
      DEBUG("Trying to reset password via IAMv2 API: %s" % url)
      resp = Session().put(
        url=url,
        data=json.dumps(
          {
            'username': 'admin',
            'old_password': PRISM_DEFAULT_PASSWORD,
            'new_password': new_password
          }
        ), headers=self.HEADERS_VALUE, verify=False)
      if not resp.ok:
        raise NuTestClientAuthenticationError(
          "Erroneous Response from IAM password change API %s" % resp.content)
    except Exception as exc:
      raise NuTestClientAuthenticationError(
        "Failed while setting password on MSP PC. %s: %s" %
        (type(exc), str(exc)))

    return resp.ok


  def __get_absolute_url(self, relative_url, version=None, namespace=None,
                         module=None, base_path=None):
    """Gets the absolute url for the request based on relative url

    Args:
      relative_url (str): relative url string
      version (str, optional): REST version to be used.
      namespace(str, optional): Namespace to which the endpoints belong
      module(str, optional): Module to which the url in a certain namespace
                             belongs.
      base_path(str, optional): Base path to be considered while forming
                                the URL.

    Returns:
      str: The absolute url to be called on the resource
    """
    # If absolute url is passed don't do anything
    if relative_url.startswith('http'):
      return relative_url

    if not version:
      version = self.version

    if hasattr(self, '_host') and self._host:
      host_url = 'https://%s' % (self._host)
    else:
      host_url = self._get_accessible_url()

    if namespace:
      url = '/'.join(part.strip('/') for part in [host_url, "api", namespace,
                                                  version, module,
                                                  relative_url])
    else:
      base_path = base_path or self.VERSION_BASE_PATH[version]
      url = '/'.join(part.strip('/') for part in [host_url, base_path,
                                                  relative_url])
    return url

  def __is_nested_base_cluster(self):
    """Method to check if cluster is nested base cluster.

    Returns: True if cluster is nested base cluster, False otherwise.
    """
    if not os.environ.get("NESTED_AHV"):
      return False

    metadata = (self._cluster.metadata if hasattr(self, '_cluster')
                else fetch_jarvis_metadata(self._svm))
    metadata = metadata or {}
    return bool(metadata.get('is_nested_base_cluster'))

  def __change_password(self, current_password, new_password):
    """
    Method to change the password.

    Args:
      current_password(str): Current password.
      new_password(str): New password.

    Returns:
      None

    Raises:
      NuTestInterfaceError: If unable to change the password.
    """
    INFO("Changing default password")
    session = Session()
    if self._is_cmsp_pc():
      self._reset_passwd_in_msp_pc(new_password)
    else:
      url = "utils/change_default_system_password"
      change_default_password_url = self.__get_absolute_url(
        url, version=PrismRestVersion.V1)
      DEBUG("Changing password from {} to {} for admin user".
            format(current_password, self.log_password(new_password)))
      response = session.post(url=change_default_password_url,
                              data=json.dumps({
                                'oldPassword': current_password,
                                'newPassword': new_password
                              }),
                              auth=(PRISM_USER, current_password),
                              headers=self.HEADERS_VALUE, verify=False)
      if not response.ok:
        ERROR("Response from password change API %s" % response.content)
        raise NuTestInterfaceError('Unable to set prism password')

    self._password = new_password
    # This is a quick fix from NuTest.
    # ENG-195449 to be resolved by Prism.
    # Per the Prism team, it can take 180s for the password to propogate.
    DEBUG("Waiting 180s for the new password to sync")
    time.sleep(180)

  def __change_password_and_check(self, new_password, retries=1):
    """
    Method to change the password and check if the password is set correctly.
    Args:
      new_password(str): New password to be set.
      retries(int): Number of attempts to change the password.
          Default: 1
    Returns:
      None
    Raises:
      NuTestInterfaceError: If unable to change the password.
    """
    for attempt in range(1 + retries):

      self.__change_password(PRISM_DEFAULT_PASSWORD, new_password)

      if self.check_auth_with_password(new_password):
        return
      elif self.check_auth_with_password(PRISM_DEFAULT_PASSWORD):
        INFO("Password is still set to default password, retrying")
      else:
        INFO("Authentication failed with {} and {} passwords."
             "Not retrying.".
             format(PRISM_DEFAULT_PASSWORD, new_password))
        break

    if attempt == retries:
      INFO("Retry attempts exceeded. Unable to change password")
    raise NuTestInterfaceError(
      "After changing the Prism password to {} and waiting for it to sync "
      "it's not usable".format(self.log_password(new_password)))

def _raise_nutest_prism_error(method, url, exc,
                              type_to_raise=NuTestPrismError):
  """
  Method to raise NuTestPrismError or its sub-classes.

  Args:
    method(str): HTTP Method
    url(str): URL string
    exc(NuTestHTTPError): NuTestHTTPError object
    type_to_raise (type): Exception type to raise, NuTestPrismError by default.

  Raises:
    NuTestPrismError by default else whatever is passed to 'type_to_raise'
  """
  DEBUG('%s request failed for %s with status code %s' %
        (method, url, str(exc.response.status_code)))
  DEBUG("Error response content: %s" % exc.response.content)

  exception_message = '%s request failed for %s with status code %s' % (
    method, url, str(exc.response.status_code))
  raise type_to_raise(exception_message, response=exc.response)

def _bracket_enclose_if_ipv6(svm_ip):
  """
  Method to enclose bracket to SVM IP if it's IPv6 IP.
  Args:
    svm_ip(str): SVM IP either in IPv4 or IPv6 format.
  Returns:
    svm_ip(str): if IP is IPv6: "[svm_ip]" else "svm_ip"
  """
  if get_ip_type(svm_ip) == "IPv6":
    svm_ip = "[%s]" % svm_ip

  return svm_ip
