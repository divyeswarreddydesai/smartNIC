"""
Copyright (c) 2018 Nutanix Inc. All rights reserved.

Author: durai.gowardhan@nutanix.com>

This is the implementation which gives us an AristaSwitchClient object.
"""

import pyeapi
from framework.lib.nulog import DEBUG
from framework.interfaces.consts import ARISTA_SWITCH_USER,\
  ARISTA_SWITCH_PASSWORD

class AristaSwitchClient(object):
  """
  This is the implementation which gives us an AristaSwitchClient object.
  """

  def __init__(self, arista_switch, host, username=ARISTA_SWITCH_USER,
               password=ARISTA_SWITCH_PASSWORD, **kwargs):
    """
    This routine is used to create instance of an entity.
    Args:
      arista_switch (AristaSwitch): AristaSwitch instance
      host (switch ip): switch ip
      username (str): Username of switch
      password (str): Password of switch
    """
    self.arista_switch = arista_switch
    self.host = host
    self.username = username
    self.password = password
    self.transport = kwargs.get("transport", "https")
    self.port = kwargs.get("port", "443")
    self._connection_obj = None

  @property
  def connection_obj(self):
    """This method need to be implemented like SSH get_connection. Pyeapi
    uses httplib module to make requests. Httplib is not thread safe.
    For multithreading, we need to use separate connection object for each
    request.

    Returns:
      Node (Node): returns Node object from pyeapi module
    """
    if self._connection_obj is None:
      self._connection_obj = pyeapi.connect(
        transport=self.transport, host=self.host, username=self.username,
        password=self.password, port=self.port, return_node=True)

    return self._connection_obj

  def invoke_api(self, entity, func_name, func_kwargs=None):
    """This method invokes appropriate entities API
    Args:
      entity (str): API exposed by pyeapi for Arista Switch
      func_name (str): Function to invoked of the entity provided
      func_kwargs (dict): args and kwargs to be passed to the function

    Returns:
      HTTPresponse (response): Returns response from entity API
    """
    if func_kwargs is None:
      func_kwargs = {}
    entity_obj = self.connection_obj.api(entity)
    if func_kwargs.get("name"):
      response = getattr(entity_obj, func_name)(func_kwargs.pop("name"),
                                                **func_kwargs)
    else:
      response = getattr(entity_obj, func_name)(**func_kwargs)

    DEBUG("response: %s" % response)
    return response
