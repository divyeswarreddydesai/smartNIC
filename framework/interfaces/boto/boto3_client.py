"""
This module provides the Boto3Client class.

Authors: dharma.surisetti@nutanix.com
         samriddhi.raj@nutanix.com
         sarang.sawant@nutanix.com

Copyright (c) 2024 Nutanix Inc. All rights reserved.
"""

import os
import boto3

from framework.lib.nulog import INFO

class Boto3Client:
  """Class to implement the Boto3Client class."""
  RETRIES = 3 # Note that boto has a built-in retry mechanism.

  def __init__(self, access_key=None, secret_key=None, region=None):
    """The initializer of the Boto3Client class.
    Args:
      access_key (str): The AWS access key.
      secret_key (str): The AWS secret key.
      region (str): The AWS region.
    """
    self.access_key = access_key or os.environ.get('AWS_ACCESS_KEY_ID')
    self.secret_key = secret_key or os.environ.get('AWS_SECRET_ACCESS_KEY')
    self.region = region or os.environ.get('AWS_DEFAULT_REGION')
    assert self.access_key, 'AWS_ACCESS_KEY_ID is not set or provided'
    assert self.secret_key, 'AWS_SECRET_ACCESS_KEY is not set or provided'
    assert self.region, 'AWS_DEFAULT_REGION is not set or provided'

  @property
  def ec2_client(self):
    """
    Method to provide the ec2 client.
    Returns:
      (obj): EC2 client object.
    """
    return boto3.client('ec2',
                        region_name=self.region,
                        aws_access_key_id=self.access_key,
                        aws_secret_access_key=self.secret_key)

  @property
  def s3_client(self):
    """
    Method to provide the S3 client.
    Returns:
      (obj): S3 client object.
    """
    return boto3.client('s3',
                        region_name=self.region,
                        aws_access_key_id=self.access_key,
                        aws_secret_access_key=self.secret_key)

  @property
  def cf_client(self):
    """
    Method to provide the cloud formation client.
    Returns:
      (obj): CloudFormation client object.
    """
    return boto3.client('cloudformation',
                        region_name=self.region,
                        aws_access_key_id=self.access_key,
                        aws_secret_access_key=self.secret_key)

  def download_file_from_s3(self, bucket_name, object_key, local_file_path):
    """Downloads a file from an S3 bucket.

    Args:
      bucket_name(str): The name of the S3 bucket.
      object_key(str): The key of the object in the bucket.
      local_file_path(str): The path to the local file where the object
      will be downloaded.

    """
    INFO("Downloading: file from S3 bucket %s at %s." % (bucket_name,
                                                         local_file_path))
    _retries = Boto3Client.RETRIES
    if os.path.exists(local_file_path):
      os.unlink(local_file_path)
    while _retries > 0:
      self.s3_client.download_file(bucket_name, object_key, local_file_path)
      if os.path.exists(local_file_path):
        break
      _retries -= 1
    assert os.path.exists(local_file_path), f'Could not find file ' + \
                                            f'{local_file_path}'
    INFO("Downloaded: %s from S3 bucket %s." % (object_key, bucket_name,))

  def create_vm(self, **kwargs):
    """
    Method to launch an EC2 Instance. This method only launches 1 instance
    at a time.

    Args:
      kwargs:
        kwargs["iam_instance_profile"] (str): IAM profile to assign to VM.
        kwargs["ami_id"] (str): AMI to use.
        kwargs["instance_type"] (str): Instance type to use.
          defaults to "t2.micro".
        kwargs["block_device_mappings] (list): The block device mapping,
          which defines the EBS volumes and instance store volumes to attach to
          the instance at launch.
        kwargs["network_interfaces_list"] (list): The network interfaces to
          associate with the instance.
        kwargs["ssh_key_name"] (str): Name of the key pair to launch the
          instance with.
        kwargs["user_data_script"] (str):  The user data script to make
          available to the instance during launch.
        kwargs["tags"] (list): The tags to apply to the resources that are
          created during instance launch.
        kwargs["wait_until_running"] (bool): Flag to wait until the VM is
          running. Defaults to True.

    Returns:
      (dict): The launched instance dictionary with boto3 run_instances()
        response syntax.
    """

    instances = self.ec2_client.run_instances(
      IamInstanceProfile=kwargs.get("iam_instance_profile"),
      ImageId=kwargs.get("ami_id"),
      InstanceType=kwargs.get("instance_type", "t2.micro"),
      MinCount=1,
      MaxCount=1,
      BlockDeviceMappings=kwargs.get("block_device_mappings"),
      NetworkInterfaces=kwargs.get("network_interfaces_list"),
      KeyName=kwargs.get("ssh_key_name"),
      UserData=kwargs.get("user_data_script"),
      TagSpecifications=kwargs.get("instance_tags")
    )

    if kwargs.get("wait_until_running", True):
      waiter = self.ec2_client.get_waiter('instance_running')
      waiter.wait(InstanceIds=[instances['Instances'][0]['InstanceId']])

    return instances['Instances'][0]

  def list_vms(self, filters=None):
    """
    Describes the EC2 Instances meeting the filter criteria. If no filter is
    specified, it will return all EC2 Instances belong to the region.

    Args:
      filters (list): The filters

    Returns:
      (list): The list of instances, each item is the an instance dictionary.
    """
    reservations = self.ec2_client.describe_instances(Filters=filters or [])
    return [instance for reservation in reservations["Reservations"]
            for instance in reservation["Instances"]]

  def create_network_interface(self, **kwargs):
    """
    Creates a network interface in the specified subnet.

    Args:
      kwargs:
        kwargs["SubnetId"] (Manadatory) (str): The ID of the subnet to associate
          with the network interface.
        kwargs["Groups"] (list): The IDs of one or more security groups.

    Returns:
      (dict): The network interface created dictionary with boto3 response
        syntax.
    """

    return self.ec2_client.create_network_interface(
      SubnetId=kwargs.get("SubnetId"),
      Groups=kwargs.get("Groups")
      )

  def attach_network_interface(self, **kwargs):
    """
    Attaches a network interface to an instance.

    Args:
      kwargs:
        kwargs["NetworkInterfaceId"] (Mandatory) (str): The ID of the network
          interface.
        kwargs["InstanceId"] (Mandatory) (str): The ID of the instance.
        kwargs["DeviceIndex"] (Mandatory) (str): The index of the device for
          the network interface attachment.

    Returns:
      (dict): Dictionary Response of attached network interface.
    """

    return self.ec2_client.attach_network_interface(
      NetworkInterfaceId=kwargs.get("NetworkInterfaceId"),
      InstanceId=kwargs.get("InstanceId"),
      DeviceIndex=kwargs.get("DeviceIndex")
      )

  def detach_network_interface(self, attachment_id):
    """
    Detaches a network interface from an instance.

    Args:
      attachment_id (Mandatory) (str): The ID of the attachment.

    Returns:
      None
    """
    self.ec2_client.detach_network_interface(AttachmentId=attachment_id)

  def delete_network_interface(self, network_interface_id):
    """
    Deletes the specified network interface. The network interface must be
    detached before deletion using detach_network_interface() method.

    Args:
      network_interface_id (Mandatory) (str): The ID of the network interface.

    Returns:
      None
    """
    self.ec2_client.delete_network_interface(NetworkInterfaceId= \
                                             network_interface_id)

  def create_tags(self, **kwargs):
    """
    Adds or overwrites only the specified tags for the specified Amazon EC2
    resources.

    Args:
      kwargs:
        kwargs["Resources"] (Mandatory) (str): The IDs of the resources,
          separated by spaces.
        kwargs["Tags"] (Mandatory) (str): The tags.

    Returns:
      None
    """

    self.ec2_client.create_tags(Resources=kwargs.get('Resources'),
                                Tags=kwargs.get('Tags'))

  def modify_instance_attribute(self, **kwargs):
    """
    Modify attribute of instance for specified Amazon EC2 resoruce.

    Args:
      kwargs:
        InstanceId(str): Instance ID of EC2 resource.
        Attribute(str): Attribute of instance to be modified.
          E.g. DisableApiTermination, DisableApiStop
        Value(str): True to enable attribute on instance. False to disable.
          Default set to False.
    """

    instance_id = kwargs.get("InstanceId")
    attribute = kwargs.get("Attribute")
    value = kwargs.get("Value", "False")
    self.ec2_client.modify_instance_attribute(InstanceId=instance_id,
                                              Attribute=attribute,
                                              Value=value)
