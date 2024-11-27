"""
IDP Service Provider API client library
"""
# Copyright (c) 2017 Nutanix Inc. All rights reserved.
#
# Author: karthik.subramaniam@nutanix.com
#
# pylint: disable=invalid-name

import urllib.parse

from framework.interfaces.http.http import HTTP
from framework.lib import nulog
from framework.interfaces.consts import IDP_CONTEXT_URL, REDIRECT_URI, \
    IDP_API_USER, IDP_API_PASSWORD, CALLBACK_URL, IDP_REDIRECT_PATH

# API Body data for Service Provider create api
inbound_authentication = {
  "type": "oauth",
  "properties": {
    "callback-url": None,
    "grant-types": "implicit iwa:ntlm password authorization_code "
                   "client_credentials refresh_token "
                   "urn:ietf:params:oauth:grant-type:saml2-bearer"
  }
}

local_and_outbound_authentication = {
  "assert-identity-using-mapped-local-subject-identifier": "false",
  "send-back-the-authenticated-list-of-idps": "false",
  "use-tenant-domain-in-local-subject-identifier": "true",
  "use-user-store-domain-in-local-subject-identifier": "true",
  "request-path-authentication": ["BasicAuthRequestPathAuthenticator"],
  "authentication-steps": [
    {
      "use-attributes": "true",
      "local": [{"name": "BasicAuthenticator"}],
      "federated": []
    },
    {
      "use-attributes": "true",
      "local": [],
      "federated": [
        {
          "name": "xi-local-idp",
          "default-authenticator": "Nutanix"
        }
      ]
    },
    {
      "use-attributes": "true",
      "local": [],
      "federated": [
        {
          "name": "xi-local-idp",
          "default-authenticator": "nutanix-role-mapper"
        }
      ]
    }
  ]
}

claim_mappings = {
  "role-claim-uri": "http://wso2.org/claims/role",
  "subject-claim-uri": "http://wso2.org/claims/emailaddress",
  "dialect": "local",
  "mappings": [
    {"local-claim": "http://wso2.org/claims/xi_role"},
    {"local-claim": "http://wso2.org/claims/default_tenant"},
    {"local-claim": "http://wso2.org/claims/federated_idp"},
    {"local-claim": "http://wso2.org/claims/givenName"},
    {"local-claim": "http://wso2.org/claims/emailaddress"},
    {"local-claim": "http://wso2.org/claims/lastName"},
    {"local-claim": "http://wso2.org/claims/scimId"}
  ]
}

class IdpServiceProvider(HTTP):
  """
  IDP service-providers api
  """
  def __init__(self, xi_ip):
    """
    Args:
      xi_ip (str): Xi Portal vm IP
    """
    super(IdpServiceProvider, self).__init__()
    self.xi_ip = xi_ip
    self.base_url = "{0}/service-providers".format(IDP_CONTEXT_URL)
    self.headers = {"content-type": "application/json"}
    self._session.auth = (IDP_API_USER, IDP_API_PASSWORD)

    self.xi_sp_name = "xi_sp_%s" % xi_ip.replace(".", "_")
    self.onprem_pc_sp_name = "onprem_pc_sp_%s" % xi_ip.replace(".", "_")

  def create_service_provider(self, sp_name, callback_url):
    """
    Create service_provider on IDP Server
    Args:
      sp_name (str) : service provider name
      callback_url (str) :  Callback url for oauth
    Returns:
      dict : Dict with client_id and client_secret
    """
    inbound_authentication['properties']['callback-url'] = callback_url
    xi_ip = urllib.parse.urlparse(callback_url).hostname
    data = {
      "service-provider-name": sp_name,
      "description": "Service Provider for %s Xi VM" % xi_ip,
      "inbound-authentication": inbound_authentication,
      "local-and-outbound-authentication": local_and_outbound_authentication,
      "claim-mappings": claim_mappings
    }
    nulog.INFO("Creating SP %s on idp-dev for %s" % (sp_name, xi_ip))
    response = self._session.post(self.base_url, json=data, verify=False)
    nulog.INFO("%s, %s" % (response.status_code, response.text))
    assert response.ok, "Create Service Provider call to IDP failed"
    return response.json()

  def get_keys_from_service_provider(self, sp_name):
    """
    Given a Service Provider name, get the oauth keys from IDP
    Args:
      sp_name (str): service provider name
    Returns:
      keys (dict)
    """
    data = {
      "service-provider-name": sp_name,
      "inbound-authentication": {"type": "oauth"}
    }
    nulog.INFO("Get Oauth Keys from IDP, SP Name: %s" % sp_name)
    response = self._session.post(self.base_url, json=data, verify=False)
    nulog.INFO("%s, %s" % (response.status_code, response.text))
    if response.ok:
      return response.json()
    else:
      return None

  def delete_service_provider(self, sp_name):
    """
    DELETE a Service Provider on IDP
    Args:
      sp_name (str): Name of the service_provider to delete
    Returns:
      None
    """
    nulog.INFO("Deleting SP %s on idp-dev" % sp_name)
    url = "{0}/{1}".format(self.base_url, sp_name)

    response = self._session.delete(url, verify=False)
    nulog.INFO("%s, %s" % (response.status_code, response.text))

  def create_xiportal_service_provider(self, xi_ip):
    """
    Create Service Provider for Xi Portal auth
    Args:
      xi_ip (str) : Xi Portal VM ip address
    Returns:
      dict : client-id , client-secret
    """
    sp_name = self.xi_sp_name
    callback_url = REDIRECT_URI.format(xi_ip=xi_ip,
                                       callback_url=CALLBACK_URL)
    return self.create_service_provider(sp_name, callback_url)

  def create_onprem_pc_service_provider(self, xi_ip):
    """
    Create Service Provider for onPrem PC pairing to Xi Portal
    Args:
      xi_ip (str) : Xi Portal VM ip address
    Returns:
      dict : client-id , client-secret
    """
    sp_name = self.onprem_pc_sp_name
    callback_url = REDIRECT_URI.format(xi_ip=xi_ip,
                                       callback_url=IDP_REDIRECT_PATH)
    return self.create_service_provider(sp_name, callback_url)

  def get_xiportal_sp_keys(self, xi_ip=None):
    """
    Get Oauth Keys for xiportal
    Args:
      xi_ip (str): Xi Portal IP address
    Returns:
      dict : client-id , client-secret
    """
    if xi_ip == None:
      sp_name = self.xi_sp_name
    else:
      sp_name = "xi_sp_%s" % xi_ip.replace(".", "_")

    sp_keys = self.get_keys_from_service_provider(sp_name)
    if sp_keys:
      return sp_keys
    else:
      return {"client-key": None, "client-secret": None}

  def get_onprem_pc_sp_keys(self, xi_ip=None):
    """
    Get Oauth Keys for xiportal
    Args:
      xi_ip (str): Xi Portal IP address
    Returns:
      dict : client-id , client-secret
    """
    if xi_ip == None:
      sp_name = self.xi_sp_name
    else:
      sp_name = "onprem_pc_sp_%s" % xi_ip.replace(".", "_")

    pc_keys = self.get_keys_from_service_provider(sp_name)
    if pc_keys:
      return pc_keys
    else:
      return {"client-key": None, "client-secret": None}

  def delete_xiportal_service_provider(self, xi_ip=None):
    """
    Delete Service Provider of the xi vm
    Args:
      xi_ip (str): Xi Portal IP address
    Returns:
      None
    """
    if xi_ip == None:
      sp_name = self.xi_sp_name
    else:
      sp_name = "xi_sp_%s" % xi_ip.replace(".", "_")

    self.delete_service_provider(sp_name)

  def delete_onprem_pc_service_provider(self, xi_ip=None):
    """
    Delete onPrem PC-Service Provider of the xi vm
    Args:
      xi_ip (str): Xi Portal IP address
    Returns:
      None
    """
    if xi_ip == None:
      sp_name = self.onprem_pc_sp_name
    else:
      sp_name = "onprem_pc_sp_%s" % xi_ip.replace(".", "_")

    self.delete_service_provider(sp_name)

  def setup_sp(self, xi_ip=None):
    """
    Create SP's for the Xi Portal IP
    Args:
      xi_ip (str): Xi Portal IP address
    Returns:
      dict
    """
    if xi_ip == None:
      xi_ip = self.xi_ip

    sp_keys = self.create_xiportal_service_provider(xi_ip)
    pc_keys = self.create_onprem_pc_service_provider(xi_ip)

    oauth_keys = dict(
      xi_vm=dict(
        IDP_CLIENT_ID=sp_keys['client-key'],
        IDP_CLIENT_SECRET=sp_keys['client-secret'],
        IDP_CALLBACK_URL=CALLBACK_URL
      ),
      flask=dict(
        IDP_CLIENT_ID=pc_keys['client-key'],
        IDP_CLIENT_SECRET=pc_keys['client-secret'],
        IDP_REDIRECT_PATH=IDP_REDIRECT_PATH
      )
    )

    return oauth_keys

  def get_sp(self, xi_ip=None):
    """
    Get SP's for the Xi Portal IP
    Use this only of SP is already created in IDP
    Args:
      xi_ip (str): Xi Portal IP address
    Returns:
      dict
    """
    if xi_ip == None:
      xi_ip = self.xi_ip

    nulog.INFO("Get Service Providers for %s" % xi_ip)
    sp_keys = self.get_xiportal_sp_keys(xi_ip)
    pc_keys = self.get_onprem_pc_sp_keys(xi_ip)

    oauth_keys = dict(
      xi_vm=dict(
        IDP_CLIENT_ID=sp_keys['client-key'],
        IDP_CLIENT_SECRET=sp_keys['client-secret'],
        IDP_CALLBACK_URL=CALLBACK_URL
      ),
      flask=dict(
        IDP_CLIENT_ID=pc_keys['client-key'],
        IDP_CLIENT_SECRET=pc_keys['client-secret'],
        IDP_REDIRECT_PATH=IDP_REDIRECT_PATH
      )
    )

    return oauth_keys

  def cleanup_sp(self, xi_ip=None):
    """
    Create SP's for the Xi Portal IP
    Args:
      xi_ip (str): Xi Portal IP address
    Returns:
      dict
    """
    if xi_ip == None:
      xi_ip = self.xi_ip

    self.delete_xiportal_service_provider(xi_ip)
    self.delete_onprem_pc_service_provider(xi_ip)
