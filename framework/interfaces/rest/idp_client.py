"""
IDP Client - Xi Portal Auth
"""
# Copyright (c) 2017 Nutanix Inc. All rights reserved.
#
# Author: durai.gowardhan@nutanix.com
#
# pylint: disable=unused-wildcard-import
# pylint: disable=no-member, invalid-name
# pylint: disable=wildcard-import

from datetime import datetime, timedelta
import urllib.parse
import threading
import jwt
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm

from framework.exceptions.nutest_error import NuTestError
from framework.interfaces.consts import IDP_USER_DEFAULT_PASSWORD, \
  REDIRECT_URI, XI_PAIRING_URI
from framework.interfaces.http.http import HTTP
from framework.lib.error_categorisation import ErrorCategory
from framework.lib import nulog

BUFFER_TIME = 100
CACHE_TOKEN = {}
SIGNING_ALGORITHM = "RS256"
try:
  jwt.register_algorithm(SIGNING_ALGORITHM, RSAAlgorithm(RSAAlgorithm.SHA256))
except ValueError:
  pass

def check_token(id_token):
  """
  Args:
    id_token (str): Token obtained from IDP server
  """
  decoded_token = jwt.decode(id_token, verify=False)
  nulog.DEBUG("Xi Role present in token? %s" % ("xi_role" in decoded_token))

class IdpClient(HTTP):
  """
  IDP Client to fetch token for Xi Auth
  """
  def __init__(self, xi_cluster, user, password=IDP_USER_DEFAULT_PASSWORD):
    """
    Args:
      xi_cluster (XiPortalCluster) : Xi Portal Cluster object
      user (str): user
      password (str): password
    """
    super(IdpClient, self).__init__()

    self.xi_cluster = xi_cluster
    self.user = user
    self.password = password
    self.idp_config = self.xi_cluster.idp_config_data
    self.url = "https://" + self.idp_config.get("IDP_IP")
    self.headers = {'content-type': "application/x-www-form-urlencoded"}

  def get_auth_code(self):
    """
    Ger authorization code from IDP
    Returns:
      code (str): Code from IDP
    Raises:
      NuTestError: If failed to get "code" from idp server.
    """
    url = self.url + "/oauth2/authorize"
    nulog.DEBUG("url: %s" % url)
    payload = dict(
      response_type="code",
      client_id=self.idp_config.get("IDP_CLIENT_ID"),
      redirect_uri=self.idp_config.get("REDIRECT_URI"),
      scope="openid"
    )
    auth = (self.user, self.password)

    response = self.post(url, data=payload, headers=self.headers,
                         auth=auth, allow_redirects=False, retries=5)
    nulog.DEBUG("%s: %s: %s" % (response.history, response.status_code,
                                response.headers))
    try:
      redirect_url = response.headers['Location']
      parsed = urllib.parse.urlparse(redirect_url)
      code = urllib.parse.parse_qs(parsed.query)['code']
      return code[0]
    except KeyError as exc:
      nulog.ERROR("%s" % str(exc))
      raise NuTestError(
        "User: %s in IDP server might not have been configured with correct "
        "attributes. Please check 'Location' key in response header for more "
        "specific information.\nresponse.headers: %s" %
        (self.user, response.headers), category=ErrorCategory.RESOURCE_STATE)

  def fetch_token(self):
    """
    Given code get the bearer token
    Args: code (str): auth code
    Returns:
       id_token (str): Return the Token got from IDP server
    """
    url = self.url + "/oauth2/token"
    auth = (self.idp_config.get("IDP_CLIENT_ID"),
            self.idp_config.get("IDP_CLIENT_SECRET"))
    payload = dict(
      grant_type="authorization_code",
      client_id=self.idp_config.get("IDP_CLIENT_ID"),
      redirect_uri=self.idp_config.get("REDIRECT_URI"),
      code=self.get_auth_code(),
      scope="openid"
      )

    response = self.post(url, data=payload, headers=self.headers,
                         auth=auth, retries=5)
    if response.status_code == 200:
      id_token = response.json().get("id_token", "not_found")
      check_token(id_token)
      return id_token
    nulog.ERROR("Failure to get token from IDP: %s" % response.text)
    return None

  def get_pairing_auth_code(self, pc_ip):
    """
    Get code for On Prem PC Pairing
    Args:
      pc_ip (str) : On-Prem PC IP
    Returns:
      code(str): Code from IDP for pairing
    """
    url = self.url + "/oauth2/authorize"
    redirect_uri = REDIRECT_URI.format(
      xi_url=self.idp_config.get("XI_URL"),
      callback_url=self.idp_config.get("IDP_REDIRECT_PATH"))
    state = REDIRECT_URI.format(
      xi_url=pc_ip,
      callback_url=self.idp_config.get("IDP_CALLBACK_URL"))

    payload = dict(
      response_type="code",
      client_id=self.idp_config.get("IDP_CLIENT_ID"),
      redirect_uri=redirect_uri,
      scope="openid",
      state=state
    )
    auth = (self.user, self.password)

    response = self.post(url, data=payload, headers=self.headers,
                         auth=auth, allow_redirects=False, retries=5)
    nulog.DEBUG("%s: %s: %s" % (response.history, response.status_code,
                                response.headers))
    redirect_url = response.headers['Location']

    parsed = urllib.parse.urlparse(redirect_url)
    code = urllib.parse.parse_qs(parsed.query)['code'][0]
    return code

  def _send(self, method, url, **kwargs):
    """Overriding the _send of http.

    Args:
      method (str): HTTP method.
      url (str): relative_url.
      kwargs:
        auth (tuple): Tuple of (username, password)
        retries (int): The retry count that has to be sent to HTTP's _send.

    Returns:
      dict: The response content loaded as a JSON.

    Raises:
      NuTestPrismError: On Prism returning error codes in the response.
      NuTestInterfaceError: On failure to connect to server or
        if Prism Services are down on server.
    """
    self._session.auth = kwargs.pop("auth", (self.user, self.password))
    return super(IdpClient, self)._send(method, url, **kwargs)

class MyNutanixDomainClient(HTTP):
  """
  XI PAIRING DOMAIN to fetch token for Xi Auth
  """
  lock = threading.RLock()
  def __init__(self, xi_cluster, user, password=IDP_USER_DEFAULT_PASSWORD):
    """
    Args:
      xi_cluster (XiPortalCluster) : Xi Portal Cluster object
      user (str): user
      password (str): password
    """
    super(MyNutanixDomainClient, self).__init__()

    self.xi_cluster = xi_cluster
    self.user = user
    self.password = password
    self.headers = {'Content-Type': 'application/json'}

  # pylint: disable=no-else-return
  def fetch_token(self):
    """
    Fetches id_token from the corresponding xi pairing domain.

    Returns:
      id_token (str): Return the Token got from xi pairing domain
    """
    cache_key = (self.xi_cluster, self.user, self.xi_cluster.my_nutanix_domain)
    token_info = CACHE_TOKEN.get(cache_key)
    with MyNutanixDomainClient.lock:
      if token_info:
        if (datetime.now() + timedelta(seconds=5)) \
                < token_info["expiration_time"]:
          return token_info["token"]
        else:
          CACHE_TOKEN.pop(cache_key)
      payload = {"username": self.user, "password": self.password}
      xi_pairing_uri = XI_PAIRING_URI.format(
        my_nutanix_domain=self.xi_cluster.my_nutanix_domain)
      response = self.post(xi_pairing_uri, json=payload, headers=self.headers,
                           retries=3, retry_interval=5)
      id_token = response.json().get("id_token", "not_found")
      check_token(id_token)
      decoded_token = jwt.decode(id_token, verify=False,
                                 algorithms=SIGNING_ALGORITHM)
      exp_time = datetime.fromtimestamp(decoded_token['exp']) - \
                 timedelta(seconds=BUFFER_TIME)
      CACHE_TOKEN.update({cache_key: {
        "expiration_time": exp_time,
        "token": id_token}})
    return id_token
