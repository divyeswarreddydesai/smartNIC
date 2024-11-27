"""
Module to implement the KubeAwsClient class.

Author: Dharma Surisetti <dharma.surisetti@nutanix.com>
        Kesireddy Shiva Reddy <kesireddy.reddy@nutanix.com>

Copyright (c) 2024 Nutanix Inc. All rights reserved.
"""
import os

from framework.interfaces.kube.kube_client import KubeClient
from framework.operating_systems.operating_system import LinuxOperatingSystem
from framework.lib.nulog import DEBUG

class KubeAwsClient(KubeClient):
  """ Class to implement the KubeAwsClient class."""

  def __init__(self, **kwargs):
    """
    The initializer of the KubeAwsClient class.

    kwargs:
      eks_cluster (str): The name of the EKS cluster.
      kube_config (str): The path to the kube config file.

    Raises:
      Exception: If the EKS Cluster name is not provided.
    """
    if not kwargs.get("kube_config"):
      self.eks_cluster = kwargs.get("eks_cluster")
      if not self.eks_cluster:
        raise Exception("EKS Cluster name is required.")
      file_name = "EKS_{}_KUBE.cfg".format(self.eks_cluster)
      self.kube_config_file = (
        os.path.join(os.environ["NUTEST_LOGDIR"], file_name))
      self.__generate_kube_config()
      kwargs["kube_config"] = self.kube_config_file
    super().__init__(kube_config=kwargs.get("kube_config"))

  @classmethod
  def update_config(cls, vm, eks_cluster, aws_region):
    """Update default kubeconfig through aws eks update-kubeconfig command.
    Args:
      vm (VM): VM object to execute the command.
      eks_cluster (str): Name of the EKS cluster.
      aws_region (str): AWS region.
    Raises:
      AssertionError: If failed to update kubeconfig.
    """
    cmd = (
      f"aws eks update-kubeconfig --region {aws_region} "
      f"--name {eks_cluster}"
    )
    DEBUG(f"Localhost >> Executing command {cmd}")
    response = vm.local_execute(cmd)
    assert response['status'] == 0, \
      f'Failed to update aws k8s cluster {eks_cluster} kubeconfig'
    DEBUG(f"Localhost >> Successfully updated kubeconfig for {eks_cluster}")

  def __generate_kube_config(self):
    """ Method to generate the kube config file.

    Raises:
      Exception: If failed to set the kube config.
    """
    # Setting the Kube config
    cmd = ('aws eks update-kubeconfig --region {0} --name {1} --kubeconfig {2}'.
           format(os.environ['AWS_DEFAULT_REGION'],
                  self.eks_cluster,
                  self.kube_config_file))
    response = LinuxOperatingSystem.local_execute(cmd)
    if response["status"] != 0:
      raise Exception(f"Failed to set kube config: {response}")
