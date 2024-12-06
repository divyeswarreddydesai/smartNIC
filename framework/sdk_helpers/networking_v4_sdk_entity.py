"""
Copyright (c) 2021 Nutanix Inc. All rights reserved.
Author: karthik.c@nutanix.com
"""

# pylint: disable=line-too-long, broad-except
# pylint: disable=no-member, too-many-locals
# pylint: disable=unused-argument
# pylint: disable=no-self-argument
# pylint: disable=access-member-before-definition
# pylint: disable=invalid-name
# pylint: disable=inconsistent-return-statements
# pylint: disable=useless-object-inheritance
# pylint: disable=protected-access

import json

from ntnx_networking_py_client import ApiClient
from ntnx_networking_py_client import Configuration
# from ntnx_prism_py_client import ApiClient as PrismApiClient
from framework.lib.decorators import retry
from framework.logging.log import DEBUG, INFO
from framework.logging.error import ExpError
# from framework.entities.rest.mixins import TaskHandlingMixin
# from framework.entities.task.task import Task, TaskStatus
# from framework.exceptions.entity_error import NuTestEntityOperationError, \
#   NuTestError
# from framework.interfaces.interface import Interface
from framework.sdk_helpers.utility_v4_task import V4TaskUtil
# from workflows.flow.FlowNG.flow_ng_constants import FlowNgConstants

# from framework.sdk_helpers.prism_api_client import PrismApiClient
# class NetworkingSdkClient(object):
#   """
#   Class to create networking SDK client for the given cluster.
#   """

#   @classmethod
#   def get_client(cls, cluster, **kwargs):
#     """
#     Create networking SDK client object.

#     Args:
#       cluster (PrismCentral): The PrismCentral cluster objects
#     kwargs:
#       username (str): The username
#       password (str): The password
#     Returns:
#       ApiClient
#     """
#     host = cluster.svm_ips[0]
#     INFO("Host details --> {}".format(host))
#     config = Configuration()
#     # Below statement is formulated because username gets returned as None when prism username is not sent
#     config.username = "admin" if kwargs.get("prism_username") is None else kwargs.get("prism_username")
#     config.password = "Nutanix.123" if kwargs.get("prism_password") is None else kwargs.get("prism_password")
#     INFO("sdk config: %s; %s; %s; %s" % (kwargs, config, config.username, config.password))
#     config.verify_ssl = False
#     config.host = host
#     config.debug = True

#     api_client_obj = ApiClient(configuration=config)
#     api_client_obj.add_default_header(header_name="Authorization",
#                                       header_value=config.get_basic_auth_token())
#     return api_client_obj


# class PrismSdkClient(object):
#   """
#   Class to create networking SDK client for the given cluster.
#   """

#   @classmethod
#   def get_prism_client(cls, cluster, **kwargs):
#     """
#     Create Prism SDK client object.

#     Args:
#       cluster (PrismCentral): The PrismCentral cluster objects
#     kwargs:
#       username (str): The username
#       password (str): The password
#     Returns:
#       PrismApiClient
#     """
#     host = cluster.svm_ips[0]
#     config = Configuration()
#     # Below statement is formulated because username gets returned as None when prism username is not sent
#     config.username = "admin" if kwargs.get("prism_username") is None else kwargs.get("prism_username")
#     config.password = "Nutanix.123" if kwargs.get("prism_password") is None else kwargs.get("prism_password")
#     INFO("sdk config: %s; %s; %s; %s" % (kwargs, config, config.username, config.password))
#     config.verify_ssl = False
#     config.host = host
#     config.debug = True

#     prism_api_client_obj = PrismApiClient(configuration=config)
#     prism_api_client_obj.add_default_header(header_name="Authorization",
#                                             header_value=config.get_basic_auth_token())
#     return prism_api_client_obj


class NotImplementedClient(object):
  """
  Dummy class
  """

  def __init__(self, client):
    """
    Args:
      client(object): instance of API client

    Raises:
      NotImplementedError
    """
    raise NotImplementedError("{}".format(client))


class NetworkingV4SDKEntity:
  """
  Base class for handling all SDK based APIs
  """

  ENTITY_NAME = "undefined"
  ENTITY_API_CLIENT = NotImplementedClient
  NETWORKING_CLIENT = {}
  V4_SPECIFIC_ENTITES = ["load_balancer_session"]

  def __init__(self, cluster,
               name=None, entity_id=None, created_new=False,
               **kwargs):
    """
    Args:
      cluster (PrismCentral): The PrismCentral cluster
      name(str): Name of the entity
      entity_id(str): UUID of the entity
      created_new(bool): attribute to indicate if this NOSTest context
                         created the entity
    """
    self._entity_id = entity_id
    self._name = name
    self._cluster = cluster
    self._created_new = kwargs.get("created_new", True)
    self._task_id = None
    self._data=kwargs.get("data",None)

    self._create_func = None
    self._get_func = None
    self._edit_func = None
    self._remove_func = None

    # Instantiate new API client per user per PC cluster
    # key = (str(cluster), str(kwargs.get("prism_username", "admin")))
    # if self.__class__.NETWORKING_CLIENT.get(key) is None:
    #   DEBUG("Instantiating new API client for PC and user: %s" % (key,))
    #   self.__class__.NETWORKING_CLIENT[key] = (
    #     NetworkingSdkClient.get_client(cluster, **kwargs))
    # self._api_client = PrismApiClient.get_api_client()
    self._api_client = self.ENTITY_API_CLIENT(
      self._cluster.api_client)

  @property
  def name(self):
    """
    Getter for _name

    Returns:
      str
    """
    return self._name

  @property
  def created_new(self):
    """
    Getter for _created_new

    Returns:
      bool
    """
    return self._created_new

  @property
  def entity_id(self):
    """
    Getter for _entity_id

    Returns:
      str
    """
    return self._entity_id

  @classmethod
  @retry(exception_err_msgs=["\\[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC\\]"], sleep_interval=2,
         retries=10)
  def list(cls, cluster, return_json=False, **kwargs):
    """
    Invoke /api/networking/v4.0.a1/config/<entity> GET via SDK.

    Args:
      cluster(PrismCentralCluster): instance of PC cluster
      return_json(bool): attribute to indicate if return has to be in json fmt

    Returns:
      [object]: Instance of the API class or json format
    """
    # Instantiate new API client for making list calls per user per PC cluster
    # key = (str(cluster), str(kwargs.get("prism_username", "admin")))
    # if cls.NETWORKING_CLIENT.get(key) is None:
    #   DEBUG("Instantiating new API client for PC and user: %s" % (key,))
    #   cls.NETWORKING_CLIENT[key] = (
    #     NetworkingSdkClient.get_client(cluster, **kwargs))
    entity_api_client = cls.ENTITY_API_CLIENT(cluster.api_client)

    if cls.ENTITY_NAME == 'routing_policy':
      fn = getattr(entity_api_client, "list_{0}s".format("routing_policie"))
    elif cls.ENTITY_NAME == 'floating_ip':
      fn = getattr(entity_api_client, "list_{0}s".format(cls.ENTITY_NAME))
    elif cls.ENTITY_NAME == 'layer2_stretch':
      fn = getattr(entity_api_client, "list_layer2_stretches")
    elif cls.ENTITY_NAME == 'routes':
      fn = getattr(entity_api_client, "list_routes_by_route_table_id")
    elif cls.ENTITY_NAME == 'bgp_routes':
      fn = getattr(entity_api_client, "list_routes_by_bgp_session_id")
    else:
      fn = getattr(entity_api_client, "list_{0}s".format(cls.ENTITY_NAME))

    response = fn(**kwargs)
    DEBUG(json.dumps(response.to_dict()))
    if return_json:
      return [entity.to_dict() for entity in response.data or []]

    entities = []
    for entity in response.data or []:
      try:
        name = entity.name
      except AttributeError:
        name = None
      uuid = entity.ext_id
      if cls.ENTITY_NAME == 'routes':
        entities.append(cls(cluster, name=name, created_new=False,
                            entity_id=uuid,
                            route_table_id=entity.route_table_reference,data=entity.to_dict()))
      else:
        entities.append(cls(cluster, name=name, created_new=False,
                            entity_id=uuid,data=entity.to_dict()))
    return entities

  def get_by_name(self, name):
    """
    Get VPC object with the given name. Returns any object if there are multiple
    VPCs with the same name. Returns None if there are not VPCs with the given
    name.

    Args:
      name (str): <> name
    Returns:
      object
    """
    routing_table_id = getattr(self, 'route_table_id', None)
    # INFO(routing_table_id)
    entities = [x for x in self.list(self._cluster,route_table_id=routing_table_id) if x.name == name]
    if entities:
      return entities[0]
    return None

  @retry(exception_err_msgs=["\\[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC\\]"], sleep_interval=2,
         retries=10)
  def create(self, async_=False, task_wait_kwargs=None, **kwargs):
    """
    Invoke /api/networking/v4.0.a1/config/<entity> POST via SDK.

    Args:
      async_(bool): field to indicate if this method should wait for task to
                   conclude
      task_wait_kwargs(dict): as needed by TaskHandlingMixin class

    Returns:
      object

    Raises:
      NuTestEntityOperationError: if create task fails.
    """
    # Create entity specific payload for POST
    if kwargs.get("bind"):
      entity = self.get_by_name(kwargs.get("name"))
      if entity:
        entity._created_new = False
        return entity
    body = self._make_create_payload(**kwargs)
    INFO(json.dumps(body.to_dict()))
    # Call entity specific create method defined by the SDK
    if self._create_func:
      fn = self._create_func
    else:
      fn = getattr(self._api_client, "create_{0}".format(self.ENTITY_NAME))
    INFO(fn)
    response = fn(body)
    # INFO(response.get())
    DEBUG(response)

    # Return TaskReference for async requests
    if async_:
      return response.data
    # Fetch task information and wait for completion. Set entity_manager
    # specific information
    # task = self._get_task(self._api_client, response_json=response.to_dict())
    
    task_id = response.to_dict()["data"]["ext_id"]
    v4_task_obj = V4TaskUtil(self._cluster)
    # task=v4_task_obj._get_task(self._api_client,task_id)
    resp = v4_task_obj.wait_for_task_completion(task_id)
    if resp.status == "FAILED":
      raise ExpError(message=resp.error_messages[0].message)
    self._name = kwargs.get("name")
    # INFO(self.get_by_name(self._name))
    self._data = self.get_by_name(self._name)
    INFO(self._data)
    self._entity_id = self._data.entity_id
    
    INFO(self._entity_id)
    self._created_new = True
    self._task_id = task_id
    return self

    # self._wait_for_task_completion(task, **(task_wait_kwargs or {}))
    # if task.status == TaskStatus.Failed:
    #   raise NuTestEntityOperationError(
    #     "Create task failed: %s" % task.error_detail, task=task)

    # ## ENTITY_TYPE_FOR_TASK is being set as VpnGateway for v4. So we need to change
    # ## from NetworkGateway to VpnGateway
    # try:
    #   if self.ENTITY_TYPE_FOR_TASK == "NetworkGateway":
    #     try:
    #       task.get_entity_id(entity_type=self.ENTITY_TYPE_FOR_TASK)
    #     except NuTestEntityOperationError:
    #       self.ENTITY_TYPE_FOR_TASK = "VpnGateway"
    # except NuTestEntityOperationError:
    #   pass

    # uuid = task.get_entity_id(entity_type=self.ENTITY_TYPE_FOR_TASK)
    # self._entity_id = uuid
    # self._name = kwargs.get("name")
    # self._created_new = True
    # self._task_id = response.to_dict().get("data").get("ext_id")
    # INFO(self._task_id)

    # return self

  @retry(exception_err_msgs=["\\[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC\\]"], sleep_interval=2,
         retries=10)
  def edit(self, async_=False, task_wait_kwargs=None, **kwargs):
    """
    Invoke /api/networking/v4.0.a1/config/<entity>/{extId} PUT via SDK.

    Args:
      async_ (bool): Field to indicate if this method should wait for task to
                    conclude.
      task_wait_kwargs (dict): As needed by TaskHandlingMixin class.
      kwargs (dict): Additional arguments supplied to method.

    Returns:
      object

    Raises:
      NuTestEntityOperationError: if update task fails.
    """
    entity_state = self.get(return_json=False)
    reserved = entity_state.get_reserved()
    etag = reserved.get("ETag")
    kwargs["entity"] = entity_state
    # Create entity specific payload for PUT
    body = self._make_update_payload(**kwargs)
    if etag:
      reserved = body.get_reserved()
      reserved["ETag"] = etag
    DEBUG("PUT request body: %s" % json.dumps(body.to_dict()))

    # Call entity specific update method defined by the SDK
    if self._edit_func:
      fn = self._edit_func
    elif self.ENTITY_NAME == 'routing_policy':
      fn = getattr(self._api_client, "{0}".format("update_routing_policy_by_id"))
    elif self.ENTITY_NAME == 'floating_ip':
      fn = getattr(self._api_client, "{0}".format("update_floating_ip_by_id"))
    else:
      fn = getattr(self._api_client, "update_{0}_by_id".format(self.ENTITY_NAME))
    response = fn(self._entity_id, body)
    DEBUG(json.dumps(response.to_dict()))

    # Return TaskReference for async requests
    if async_:
      return response.data

    try:
      # task = self._get_task(self._api_client, response_json=response.to_dict())
      # if self.ENTITY_NAME in self.V4_SPECIFIC_ENTITES:
      #   task_id = response.to_dict()["data"]["ext_id"]
      #   v4_task_obj = V4TaskUtil(self._cluster)
      #   resp = v4_task_obj.wait_for_task_completion(task_id)
      #   return resp.status

      # self._wait_for_task_completion(task, **(task_wait_kwargs or {}))
      # if task.status == TaskStatus.Failed:
      #   INFO("Update task failed: %s" % task.error_detail)
      #   return task
      # task = self._get_task(self._api_client, response_json=response.to_dict())
    
      task_id = response.to_dict()["data"]["ext_id"]
      v4_task_obj = V4TaskUtil(self._cluster)
      task=v4_task_obj._get_task(self._api_client,task_id)
      
      resp = v4_task_obj.wait_for_task_completion(task_id)
      if resp.status == "FAILED":
        INFO("Update task failed: %s" % resp)
      self._name = kwargs.get("name")
      self._entity_id = task_id
      self._created_new = True
      self._task_id = task_id
      return resp.status

    except Exception as err:
      INFO(err)
      if hasattr(err, "entity_obj"):
        entity_obj = err.entity_obj
        DEBUG("entity_obj=%s" % entity_obj)
      raise err

  @retry(exception_err_msgs=["\\[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC\\]"], sleep_interval=2,
         retries=10)
  def get(self, return_json=True):
    """
    Invoke /api/networking/v4.0.a1/config/<entity>/{extId} GET via SDK.

    Args:
      return_json(bool): If response is needed in json format

    Returns:
      object
    """
    if self._get_func:
      fn = self._get_func
    else:
      fn = getattr(self._api_client, "get_{0}_by_id".format(self.ENTITY_NAME))
    response = fn(self._entity_id)
    DEBUG(json.dumps(response.to_dict()))
    if return_json:
      response = response.data.to_dict()
      return response

    return response.data

  @retry(exception_err_msgs=["\\[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC\\]"], sleep_interval=2,
         retries=10)
  def remove(self, async_=False, task_wait_kwargs=None, **kwargs):
    """
    Invoke /api/networking/v4.0.a1/config/<entity>/{extId} DELETE via SDK.

    Args:
      async_(bool): field to indicate if this method should wait for task to
                   conclude
      task_wait_kwargs(dict): as needed by TaskHandlingMixin class

    Returns:
      object

    Raises:
      NuTestEntityOperationError: if delete task fails.
    """
    # Call entity specific delete method defined by the SDK
    if self._remove_func:
      fn = self._remove_func
    else:
      fn = getattr(self._api_client, "delete_{0}_by_id".format(self.ENTITY_NAME))
    response = fn(self._entity_id)
    DEBUG(json.dumps(response.to_dict()))

    # Return TaskReference for async requests
    if async_:
      return response.data

    # Fetch task information and wait for completion.
    # task = self._get_task(self._api_client, response_json=response.to_dict())
    # task=v4_task_obj._get_task(self._api_client,task_id)
    
    # if self.ENTITY_NAME in self.V4_SPECIFIC_ENTITES:
    task_id = response.to_dict()["data"]["ext_id"]
    v4_task_obj = V4TaskUtil(self._cluster)
    resp = v4_task_obj.wait_for_task_completion(task_id)
    if resp.status == "FAILED":
      raise ExpError(
        "Delete task failed: %s" % resp)
    return resp.status

    # self._wait_for_task_completion(task, **(task_wait_kwargs or {}))
    # if task.status == TaskStatus.Failed:
    #   raise NuTestEntityOperationError(
    #     "Delete task failed: %s" % task.error_detail)

  def _make_create_payload(self, **kwargs):
    """
    This method has to be overridden by sub class

    Raises:
      NotImplementedError
    """
    raise NotImplementedError

  def _make_update_payload(self, **kwargs):
    """
    This method has to be overridden by sub class

    Raises:
      NotImplementedError
    """
    raise NotImplementedError

  # def _get_task(self, http_client, response_json):
  #   """
  #   Get task for a POST/PUT/DELETE request

  #   Args:
  #     http_client(object): API client
  #     response_json(object): Response from POST/PUT/DELETE

  #   Returns:
  #     Task
  #   """
  #   task_uuid = response_json["data"]["ext_id"]
  #   # Remove 'ZXJnb24=:' prefix (component identifier) from task uuid if present
  #   # Reference: https://docs.google.com/document/d/1HwHh0Kf7P9BSApIqa24b0FepfPpsO9z3G7giOYvqWpw
  #   # Component identifiers were introduced in the v4 APIs and are not backwards
  #   # compatible with earlier API versions
  #   if ':' in task_uuid:
  #     task_uuid = task_uuid.split(':')[1]
  #   task = Task(self._cluster, interface_type=Interface.REST,
  #               task_id=task_uuid)
  #   return task
