"""
Module to implement the KubeClient class.

Author: Dharma Surisetti <dharma.surisetti@nutanix.com>
        Kesireddy Shiva Reddy <kesireddy.reddy@nutanix.com>

Copyright (c) 2024 Nutanix Inc. All rights reserved.
"""
#pylint: disable=no-self-use

import os

import kubernetes
from kubernetes.config import ConfigException

from framework.interfaces.consts import DEFAULT_KUBE_CONFIG
from framework.lib.decorators import retry
from framework.lib.nulog import ERROR


class KubeClient:
  """ Class to implement the KubeClient class."""

  def __init__(self, kube_config):
    """ The initializer of the KubeClient class.
     Args:
       kube_config (str): The path to the kube config file.
    """
    self.kube_config = kube_config or DEFAULT_KUBE_CONFIG
    self.load_kube_config()

  @property
  def kube_client(self):
    """ Method to provide the kubernetes client.

    Returns:
      obj: Kubernetes client object.
    """
    return kubernetes.client

  @property
  def kube_core_v1_api(self):
    """ Method to provide the kubernetes core v1 API.
    Returns:
      obj: Kubernetes core v1 API object.
    """
    return self.kube_client.CoreV1Api()

  @property
  def kube_core_v1_api_client(self):
    """ Method to provide the kubernetes API client.

    Returns:
      obj: Kubernetes API client object.
    """
    return self.kube_core_v1_api.api_client

  @property
  def kube_custom_objects_api(self):
    """ Method to provide the kubernetes custom objects API.

    Returns:
      obj: Kubernetes custom objects API object.
    """
    return self.kube_client.CustomObjectsApi()

  @property
  def kube_storage_v1_api(self):
    """ Method to provide the kubernetes storage v1 API.

    Returns:
      obj: Kubernetes storage v1 API object.
    """
    return self.kube_client.StorageV1Api()

  @retry(exception_list=[ConfigException], retries=3,
         sleep_interval=10)
  def load_kube_config(self):
    """ Method to load the kube config.

    Raises:
      Exception: If kube config file is not found.
    """
    if not os.path.exists(self.kube_config):
      raise Exception(f"Kube config file not found: {self.kube_config}")
    try:
      kubernetes.config.load_kube_config(config_file=self.kube_config)
    except Exception as exc:
      ERROR(f"Failed to load kube config: {str(exc)}")
      raise
