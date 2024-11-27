"""
Copyright (c) 2024 Nutanix Inc. All rights reserved.
Author: himanshu.chandola@nutanix.com
"""

import time
from ntnx_prism_py_client import ApiClient as PrismApiClient
# from ntnx_prism_py_client import configuration
from ntnx_prism_py_client import TasksApi
from ntnx_networking_py_client import ApiClient
from ntnx_networking_py_client import configuration as networkingConfig
from ntnx_networking_py_client import TaskReference
from ntnx_networking_py_client.models.networking.v4.config import TaskReferenceApiResponse
# from ntnx_networking_py_client.api import LoadBalancerSessionsApi
# from framework.exceptions.entity_error import NuTestEntityOperationTimeoutError
from framework.interfaces.consts import ADMIN_PRISM_USER, ADMIN_PRISM_PASSWORD
from framework.logging.log import INFO
from framework.logging.error import ExpError
class V4TaskUtil:
  """
    Utility for v4 task related queries
  """
  def __init__(self, cluster):
    """
      Initial setup
      Args:
        cluster(Object): pc_cluster obj

    """
    self.cluster = cluster
    # config = configuration.Configuration()
    nw_config = networkingConfig.Configuration()
    

    nw_config.host = self.cluster.ip
    nw_config.port = 9440
    nw_config.username = ADMIN_PRISM_USER
    nw_config.password = ADMIN_PRISM_PASSWORD
    nw_config.verify_ssl = False
    nw_config.debug = True
    nw_config.ssl_ca_cert=None
    nw_config.cert_file=None
    nw_config.key_file=None
    # self.prism_api_client = PrismApiClient(config)
    self.api_client = PrismApiClient(configuration=nw_config)

  def wait_for_task_completion(self, ext_id, timeout=120):
    """
      Waits for the task to be completed
      Args:
        ext_id(str): task id of the entity
        timeout(int): timeout to wait for task to complete
      Returns:
        object
    """
    start_time = time.time()
    poll_on_states = ["QUEUED", "RUNNING", "PENDING"]
    start_time = time.time()
    while time.time()-start_time < timeout:
      resp = TasksApi(api_client=self.api_client)\
              .get_task_by_id(extId=ext_id)
      INFO("Waiting for task with UUID: %s." % ext_id)
      INFO("Percent complete: %s" % resp.data.progress_percentage)
      if resp.data.status not in poll_on_states:
        break
      time.sleep(5)

    else:
      raise ExpError(
        "Timed out waiting for the task with uuid %s." % ext_id)

    return resp.data
  def _get_task(self, api_client,ext_id):
    """
      Fetches the status of the task
      Args:
        ext_id(str): task id of the entity
      Returns:
        str
    """
    
    resp = TaskReference(ext_id=ext_id)
    INFO(resp)
    return resp.data
  def get_load_balancer_list(self):
    """
      List load balancer sessions on the cluster
      Returns:
          resp.data

    """
    INFO("Getting list of load balancer session.")
    resp={"data":{}}
    # resp = LoadBalancerSessionsApi(api_client=self.api_client)\
    #         .list_load_balancer_sessions()
    return resp.data

  def load_balancer_session_uuid(self, entity_name):
    """
      Fetches entity id
      Args:
        entity_name(int): name of the entity
      Returns:
        uuid(str)
    """
    lb_list = self.get_load_balancer_list()
    for lb in lb_list:
      if lb.name == entity_name:
        ext_id = lb.ext_id
    return ext_id

  def get_entity_id(self, entity_type, entity_name):
    """
      Fetches entity id
      Args:
        entity_type(str): type of entity
        entity_name(int): name of the entity
      Returns:
        uuid(str)
    """
    func_name = entity_type + "_uuid"
    func_obj = getattr(self, func_name)
    return func_obj(entity_name)
