"""Module for a no-op stat recorder.
"""
# Copyright (c) 2021 Nutanix Inc. All rights reserved.

# Author: sudharshan.dm@nutanix.com

from .base_stat_recorder import BaseStatRecorder

class NullRecorder(BaseStatRecorder):
  """Recorder for no-op usage.
  """
  def __init__(self, filepath=None):
    """Initializer.

    Args:
      filepath (str): Ignored.
    """

  def add_http_request(self, method, url):
    """Record an HTTP request.

    Args:
      method (str): Ignored.
      url (str): Ignored.
    """

  def remove_http_request(self, request_doc_id):
    """Delete an HTTP request.

    Args:
      request_doc_id (int): Ignored.
    """

  def add_http_response(self, request_doc_id, response):
    """Record an HTTP response.

    Args:
      request_doc_id (int): Ignored.
      response (requests.Response): Ignored.
    """

  def add_ssh_command(self, host, command):
    """Record an SSH command execution.

    Args:
      host (str): Ignored.
      command (str): Ignored.
    """

  def add_ssh_result(self, command_doc_id, exit_status, stdout, stderr):
    """Record an SSH commmand execution result.

    Args:
      command_doc_id (int): Ignored.
      exit_status (int): Ignored.
      stdout (str): Ignored.
      stderr (str): Ignored.
    """

  def add_inbound_scp_record(self, host, remote_path, local_path):
    """Add an inbound SCP transfer record.

    Args:
      host (str): SCP hostname. Ignored.
      remote_path (str): File path on the remote host to transfer from. Ignored.
      local_path (str): File path on the local host to transfer to. Ignored.
    """

  def add_outbound_scp_record(self, host, local_path, remote_path):
    """Add an outbound SCP transfer record.

    Args:
      host (str): SCP hostname. Ignored.
      local_path (str): File path on the local host to transfer from. Ignored.
      remote_path (str): File path on the remote host to transfer to. Ignored.
    """

  def add_scp_result(self, scp_doc_id):
    """Add an SCP transfer result.

    Args:
      scp_doc_id (int): Document ID of the corresponding SCP transfer record.
                        Ignored.
    """

  def add_process_record(self, process):
    """Add a process record.

    Args:
      process (psutil.Process): The process to add stats of.
    """
