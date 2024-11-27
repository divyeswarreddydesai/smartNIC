"""Python interface for running commands on NXCTLCLI.

Copyrights (c) Nutanix Inc. 2024

Authors: sarang.sawant@nutanix.com,

"""

import json
import os
import sys
import time
import socket
import subprocess
from typing import Dict

import boto3

from kubernetes import client, config
from kubernetes.client.api_client import ApiClient
from botocore.exceptions import ClientError

from framework.lib.package_handler import PackageHandler
from framework.exceptions.interface_error import NuTestNxctlError
from framework.exceptions.interface_error import NuTestNxctlAuthenticationError
from framework.exceptions.interface_error import \
  NuTestCommandExecutionError, NuTestSSHConnectionTimeoutError
from framework.exceptions.nutest_value_error import NuTestValueError
from framework.lib.tester_envs import get_execution_environment
from framework.interfaces.base_cli import BaseCLI
from framework.operating_systems.operating_system.linux_operating_system \
  import LinuxOperatingSystem
from framework.interfaces.kube.kube_aws_client import KubeAwsClient
from framework.entities.k8s.service import ServiceEntity
from framework.lib.nulog import DEBUG, ERROR, INFO, TRACE, WARN

# pylint: disable=invalid-sequence-index, arguments-differ

class Nxctl(BaseCLI):
  """This class defines a standard protocol to use NXCTL commands.
  """
  PATH = '/usr/bin/nxctl'
  CONFIG_PATH = os.path.expanduser('~/.nxctlconfig')
  ERROR_CODES = []
  NXCTL_SVC_NAME = 'nxctl-svc'
  RETRIES = 3
  # Default exceptions to retry on if interface retries are enabled.
  DEFAULT_RETRY_EXCEPTIONS = [
    NuTestSSHConnectionTimeoutError,
    NuTestNxctlError,
    NuTestNxctlAuthenticationError
  ]

  def __init__(self, nucas_cluster_name=None, **kwargs):
    """Initialize NXCTLCLI.

    Args:
      nucas_cluster_name(str): The name of the cluster.
      **kwargs:
        vm(LinuxOperatingSystem): LinuxOperatingSystem Object supporting
        execution of operations on Jumphost and locally on tester.
        is_local_nxctl(bool): If nxctl is installed on testervm then true.
    Raises:
      NuTestValueError: when either cluster or jumphost is not provided
    """
    self.nucas_cluster_name = nucas_cluster_name
    self.host = None
    self.local_nxctl = kwargs.get('is_nxctl_local')
    self._vm = kwargs.get('vm') if kwargs.get('vm') else LinuxOperatingSystem()
    super(Nxctl, self).__init__(**kwargs)
    infra_env, _ = get_execution_environment()
    self.ncs_aws_env = kwargs.setdefault("environment", infra_env)
    self._region = infra_env.region_name

  @staticmethod
  def update_nxctl_lb_sg(lb_svc_name, tester_subnet_cidr,
                         region_name=None):
    """ Update the security group of the nxctl load balancer to allow
    connections from the tester subnet.
    Args:
      lb_svc_name(str): The name of the load balancer service.
      tester_subnet_cidr(str): The CIDR of the tester subnet.
      region_name(str): The region name.
    Raises:
      ClientError: If boto client encounters error.
      If the security group rule already exists a warning is logged and
      exception is not reraised.
    """
    elb = boto3.client('elbv2', region_name=region_name)
    _client = boto3.client('ec2', region_name=region_name)
    lbs = elb.describe_load_balancers(PageSize=128)
    lbs = lbs['LoadBalancers']
    svc_lb: Dict = dict()
    for lb in lbs:
      if lb['DNSName'] == lb_svc_name:
        svc_lb = lb
        break
    sg = svc_lb['SecurityGroups'][0]
    response = _client.describe_security_groups(GroupIds=[sg])
    security_group = response["SecurityGroups"][0]
    new_rule = {
      "IpProtocol": "-1",
      "FromPort": -1,
      "ToPort": -1,
      "IpRanges": [{"CidrIp": tester_subnet_cidr}]
    }

    existing_rules = security_group["IpPermissions"]
    try:
      existing_rules.append(new_rule)
      _client.authorize_security_group_ingress(
        GroupId=sg, IpPermissions=[new_rule]
      )
    except ClientError as ce:
      if ce.response["Error"]["Code"] == "InvalidPermission.Duplicate":
        WARN("Ingress rule already exists.")
      else:
        raise ce

  #pylint: disable=broad-except
  def configure(self, **kwargs):
    """
    Configure nxctl on the client
    Returns:
      bool: True if the configuration is successful, False otherwise.
    """
    eks_cluster = kwargs.get('eks_cluster', os.environ.get('EKS_CLUSTER'))
    region = kwargs.get('region')
    output = ''
    try:
      install_pkg = PackageHandler.get_resource_path(
        'framework/scripts/ncs_tester_install.sh')
      response = self._vm.local_execute(f"sh {install_pkg}")
      output = response['stdout']
      resp_code = response['status']
      assert resp_code == 0, f'Failed to install NCS Prerequisite RPM {output}'
    except Exception as err:
      TRACE(f"Execution failed:{err}")
      raise NuTestNxctlError(f"Failed to install NCS Prerequisite RPM {err}")

    try:
      response = self._vm.local_execute(f"rpm -qa | grep nxctl")
      output = response['stdout']
      resp_code = response['status']
      assert resp_code == 0, f'Failed to install nxctl {output}'
    except Exception as err:
      TRACE(f"Nxctl Configure failed:{err}")
      raise NuTestNxctlError(f"Failed to install NCS Prerequisite RPM {err}")

    # load k8s config
    white_list_ip = socket.gethostbyname(socket.gethostname())
    tester_subnet_cidr = f"{white_list_ip}/32"
    KubeAwsClient.update_config(self._vm, eks_cluster, region)
    # get the lb service name
    api_client = ApiClient()
    kube_client = Nxctl._get_kube_corev1_api_client()
    oper = ServiceEntity(api_client, kube_client)
    nxctl_svc = oper.get_service(svc_name=Nxctl.NXCTL_SVC_NAME)
    nxctl_svc = nxctl_svc.status.load_balancer.ingress[0].hostname
    Nxctl.update_nxctl_lb_sg(nxctl_svc, tester_subnet_cidr, region_name=region)
    return bool(self._configure(eks_cluster, region=region))

  def check_nxctl_status(self):
    """
    Check if nxctl is configured.

    Returns:
      bool: True if the service is up, False otherwise.
    """
    try:
      response = self._vm.local_execute(f"{Nxctl.PATH} cluster list")
      output = response['stdout']
      assert response['status'] == 0, f'Failed to list clusters {output}'
      clusters = json.loads(output)
      assert clusters, 'Cluster list is empty'
      INFO(f"NXCTL: NCS service is up. Cluster list is {clusters}")
      return True
    except Exception as fault:
      TRACE(str(fault))
      return False

  # pylint: disable=too-many-arguments, too-many-locals
  def execute(self, entity, cmd, retries=None, timeout=300,
              log_response=True, session_timeout=10,
              close_ssh_connection=False, parse_output=False, **kwargs):
    """This method executes a NXCTL command.
    1. Forms the cmd to run
    2. Get the execution params from test config and override if not implicitly
       passed in the function call.
    4. Try to execute the CMD on the host or JumpHost with retries.

    Args:
      entity(str): The entity on which the cmd is run on.
      cmd(str): The cmd that will be executed.
      retries(int, optional): The number of retries to be attempted for command
                            execution.
                            Default: Taken from global test settings.
      timeout(int, optional): Timeout in seconds for the command to be executed.
                              Default: 60 secs
      log_response (bool, Optional): True when response is supposed to be
                                     logged, else False.
      session_timeout (timeout, Optional): Timeout for opening the channel.
                                           Defaults to 10 seconds.
      close_ssh_connection (bool, Optional): Flag to set whether to close the
      SSH connection used for command execution. False by default.
      parse_output (bool, Optional): Flag to set whether to parse the output
      kwargs(dict): The key-value pairs that will be used in cli command.

    Returns:
      This routine returns a dictionary with 'status' and 'stdout' of the
      CLI command executed.

    Raises:
      NuTestNxctlError: If command execution fails with nxctl error
      NuTestNxctlAuthenticationError: If cmd execution fails with auth error.
      NuTestSSHConnectionError: If cmd execution fails due to connection error.
      NuTestSSHConnectionTimeoutError: If cmd execution fails due to ssh
        connection timeout error.
    """

    # config_retries defines the number of time a CLI command will be retried
    # in case it throws NuTestCommandExecutionError.
    config_retries = self._config.get('interface_retries', 1)
    vm = None
    # 1. Forms the cmd from the cli cmd format.
    cmd = self._get_cmd(entity, cmd, **kwargs)
    # 2. Get the execution params from test config and override if not
    # implicitly passed in the function call.
    if not retries:
      retries = 1

    # retry_interval defines the sleep duration in seconds between retries.
    retry_interval = self._config.get('interface_retry_interval', 10)

    # interface_retry_on_exception_list defines the list of exceptions
    # to do retries on. The list is collection of exception class names
    # passed as strings. We will convert the strings to class names if
    # they have been imported rightly above. Any class passed and not
    # imported here would act like it was never passed and exception
    # will be raised when received.
    custom_exceptions = \
      self._config.get('interface_retry_on_exception_list', [])
    retry_exceptions = Nxctl.DEFAULT_RETRY_EXCEPTIONS

    for custom_exception in custom_exceptions:
      try:
        exp_class = getattr(sys.modules[__name__], custom_exception)
        retry_exceptions.append(exp_class)
      except AttributeError:
        ERROR("%s not imported correctly" % custom_exception)
        continue

    # 4. Try to execute the CMD on the host or jumphost found with retries.
    vm = self._vm
    attempt = 0
    result = None
    while attempt <= config_retries:
      try:
        attempt += 1
        DEBUG("Executing %s, VM: %s, Attempt: %s" % (cmd, vm, attempt))
        result = self._execute(
          vm, cmd, retries=retries, timeout=timeout,
          log_response=log_response,
          session_timeout=session_timeout,
          close_ssh_connection=close_ssh_connection,
          parse_output=parse_output,
          interactive=kwargs.get('interactive'),
          prompt=kwargs.get('prompt')
        )
        return result

      # pylint: disable=broad-except
      except Exception as exception:
        # Python3 clears the above 'exception' object once its out of scope
        # as it now holds a reference within it for the exception traceback.
        # We copy the exception to another object and reset its traceback
        # pointer to allow it to be garbage collected once the except clause
        # is out of scope. The copied exception object can be referenced
        # from outer scopes.
        exc = exception
        exc.__traceback__ = None
        DEBUG("Received exception %s: %s" % (type(exception), exception))
        if isinstance(exception, tuple(retry_exceptions)):
          time.sleep(retry_interval)
          vm = LinuxOperatingSystem()
        else:
          exc = NuTestCommandExecutionError(
            "Command: %s. Result %s" % (cmd, result)
          )
          exc.command = cmd
          exc.result = result
          raise exc

  @staticmethod
  def _get_kube_corev1_api_client(kube_config_path=None):
    """
    Initialize k8s client.
    Args:
      kube_config_path(str): Path to kubeconfig file.
    Returns:
      CoreV1Api: CoreV1Api object.
    """
    _client = None
    if not kube_config_path:
      kube_cfg = os.path.expanduser('~/.kube/config')
    else:
      kube_cfg = kube_config_path
    _client = client.CoreV1Api(
      config.load_kube_config(kube_cfg))
    return _client

  def _execute(self, vm, cli_cmd, log_response=True,
               parse_output=False, **kwargs):
    """This method is used to execute a NXCTL command on a
    localhost or jumphost.
    1. Execute the cmd via ssh on the jumphost or locally.
    2. Try to parse the result of the NXCTL cmd and return output
    Args:
      vm(LinuxOperatingSystem): Host on which the cmd is executed.
      cli_cmd(str): CLI command to be executed.
      log_response (bool, Optional): True when response is supposed to
      be logged, else False.
      parse_output (bool, Optional): Flag to set whether to parse the output
      kwargs:
        retries(int): Number of retries.
        timeout(int): Timeout for the cmd.

    Returns:
       dict: Dictionary with status and output.

    """
    confirmation_msgs = ["Are you sure you want", 'Please confirm']
    # Execute the cmd via ssh on the jumphost
    if not self.local_nxctl:
      if not kwargs.get('interactive'):
        # SSH class don't support interactive and prompt parameters
        kwargs.pop('interactive', None)
        kwargs.pop('prompt', 'y')
        result = vm.execute(cli_cmd, log_response=log_response, **kwargs)
      else:
        shell_timeout = 20
        sleep_timer_standard = 5
        prompt = kwargs.pop('prompt')
        channel = vm.get_interactive_channel()
        vm.send_to_interactive_channel(command=cli_cmd,
                                       interactive_channel=channel)
        time.sleep(sleep_timer_standard)
        result = vm.receive_from_interactive_channel(channel)
        confirmed = any(msg in result for msg in confirmation_msgs)
        if confirmed:
          vm.execute_on_interactive_channel(
            prompt, channel, "", shell_timeout)
          result = vm.receive_from_interactive_channel(
            interactive_channel=channel
          )
        result = dict(stdout=result, status=0, stderr='')
    else:
      if kwargs.get('interactive'):
        result = vm.local_interactive_execute(
          cli_cmd, prompt=kwargs.get('prompt')
        )
      else:
        result = vm.local_execute(cli_cmd)
    # Try to parse the result and return the output
    if parse_output:
      return self._parse_output(cli_cmd, result)
    return result

  def _configure(self, eks_cluster, region):
    """
    Set permissions, configure nxctl.
    Args:
      eks_cluster(str): The name of the eks cluster.
      region(str): The region name.
    Returns:
      bool: True if the service is up, False otherwise.
    Raises:
      NuTestNxctlError: If command execution fails with nxctl error
      OSError: If command execution fails with OSError.
      AssertionError: If command execution fails with AssertionError.
    """
    try:
      try:
        cfg_update = f"{Nxctl.PATH} config update {eks_cluster} -r {region}"
        DEBUG(f"localhost >> Executing {cfg_update}")
        response = self._vm.local_execute(cfg_update)
        output = response['stdout']
        ret_code = response['status']
      except subprocess.CalledProcessError as grepexc:
        TRACE(f"error code {str(grepexc.returncode)}, {str(grepexc.output)}")
      assert ret_code == 0, f'Failed update config nxctl {Nxctl.CONFIG_PATH}'
      INFO(f"NXCTL: Configured successfully and output is {output}")
      return True
    except OSError as ex:
      TRACE(f"Execution of command nxctl config update failed:{ex}")
      return False

  # pylint: disable=no-else-return
  def _get_cmd(self, entity, cli_cmd, **kwargs):
    """Forms the CLI specific cmd by adding the correct formatting for entity
    operation and arguments
    Args:
      entity (str): Name of the entity used in the cmd.
      cli_cmd (str): The operation string used in the cmd.
      kwargs (dict): kwargs for the cli_cmd
    Returns:
      str: the cmd string
    Raises:
      NuTestValueError: If the entity is not valid.
    """
    kwargs.setdefault('option', cli_cmd)
    if entity == 'cluster':
      return NxctlCommandBuilder().build_cluster_command(**kwargs)
    elif entity == 'config':
      return NxctlCommandBuilder().build_config_command(**kwargs)
    raise NuTestValueError("Invalid entity %s" % entity)

  def _parse_output(self, cmd, response):
    """Parses the output of the nxctl command response
    Args:
      cmd(str): The cmd that was executed.
      response(str): The raw output of the cmd

    Returns:
      dict: output of the cmd

    Raises:
      NuTestCommandExecutionError
    """
    try:
      if response['stdout'] and isinstance(response['stdout'], (str, bytes)):
        response['stdout'] = json.loads(response['stdout'])
    except json.JSONDecodeError:
      TRACE(f"Failed to parse the output of the command {cmd}")
    except ValueError:
      raise NuTestCommandExecutionError("Nxctl command execution failed: "
                                        "cmd: %s Error: %s" %
                                        (cmd, response['stdout']),
                                        response=response['stdout'])
    if response['status'] == 0:
      return response['stdout']

    raise NuTestCommandExecutionError("Nxctl command execution failed: "
                                      "cmd: %s Error: %s" %
                                      (cmd, response['stderr']),
                                      response=response['stdout'])

class NxctlCommandBuilder:
  """class to build Nxctl command.
  """
  commands = ['cluster', 'config']

  options = {
    'cluster' : ['collect-logs', 'info', 'list', 'start', 'stop', 'pods',
                 'get-events', 'pc-status', 'expand', 'remove-node',
                 'replace-node', 'add-disk', 'replace-disk', 'upgrade'],
    'config': ['set-token', 'use-context', 'update'],
  }
  command_switches_short = {
    'expand' : ['n'],
    'remove-node' : ['n', 'f'],
    'replace-node' : ['n', 'f'],
    'pods' : ['g', 'n', 'w'],
    'collect-logs': ['d', 'l', 'k'],
  }
  command_switches = {
    'expand' : ['nodeCount'],
    'remove-node' : ['node', 'force'],
    'replace-node' : ['node', 'force'],
    'pods' : ['grouping', 'namespace', 'worker-node'],
    'upgrade': ['component', 'repo', 'version'],
    'collect-logs': ['duration', 'logbay-flags', 'skip-logbay']
  }
  switches = ['o', 'help', ]

  def __init__(self):
    """Initialize the NxctlCommandBuilder object.
    """
    self.parent_cmd = ['nxctl']
    self.current_options = list()

  def build_command(self, cmd: str, opt: str, name: str, **kwargs):
    """ Build options dict from the user specified options.
    Args:
    cmd(str): nxctl command like config or cluster.
    opt(str): nxctl option are subcommands like list, info, etc.
    name(str,Optional): cluster name or eks cluster name or context name.
    Depends up the caller function which command it intends to build.
    **kwargs:
      output(str): Output type like json and yaml. Defaults to json.
      help(str): Defaults to None if the key does not exists in kwargs
    Returns:
      list: The list of command options.
    Raises:
      ValueError: If the command or option is invalid.
    """
    if cmd not in NxctlCommandBuilder.commands:
      raise ValueError(
        f"Invalid nxctl command {cmd}. It must be config or cluster")
    self.parent_cmd += [cmd]
    if opt not in self.options.get(cmd):
      raise ValueError(
        f"Invalid nxctl option {opt}. "
        f"It must be one of {NxctlCommandBuilder.options[cmd]}")
    if opt in ('list', 'collect-logs'):
      self.parent_cmd += [opt]
    else:
      self.parent_cmd += [opt, name]
    for key in kwargs:
      if opt in NxctlCommandBuilder.command_switches_short and \
        key in NxctlCommandBuilder.command_switches_short.get(opt):
        self.current_options += [
          f"-{key} " + str(kwargs[key]) if kwargs[key] else f"-{key} "]
    for key in kwargs:
      if opt in NxctlCommandBuilder.command_switches and \
        key in NxctlCommandBuilder.command_switches.get(opt):
        self.current_options += [
          f"--{key} " + str(kwargs[key]) if kwargs[key] else f"--{key} "]
    for key in kwargs:
      if key in NxctlCommandBuilder.switches:
        self.current_options += [
          f"-{key} " + str(kwargs[key]) if kwargs[key] else f"-{key} "]
    return self.parent_cmd + self.current_options

  def build_cluster_command(self, **kwargs) -> str:
    """Builds the specifed nxctl cluster command.
    Args:
    **kwargs:
      cluster(str): The name of the cluster.
      option(str): The option to be used.
    Returns:
      str: The cluster command string.
    """
    self.parent_cmd = ['nxctl']
    self.current_options = list()
    cluster_name = kwargs.get('cluster')
    if 'cluster' in kwargs:
      kwargs.pop('cluster')
    opt = kwargs.get('option')
    self.parent_cmd = self.build_command(
      'cluster', opt, cluster_name, **kwargs
      )
    return ' '.join(self.parent_cmd)

  def build_config_command(self, **kwargs) -> str:
    """Builds the specifed nxctl config command.
    Args:
    **kwargs:
      cluster(str): The name of the cluster.
      option(str): The option to be used.
    Returns:
      str: The config command string.
    """
    self.parent_cmd = ['nxctl']
    self.current_options = list()
    cluster_name = kwargs.get('cluster')
    if 'cluster' in kwargs:
      kwargs.pop('cluster')
    opt = kwargs.get('option')
    self.parent_cmd = self.build_command(
      'config', opt, cluster_name, **kwargs
      )
    return ' '.join(self.parent_cmd)
