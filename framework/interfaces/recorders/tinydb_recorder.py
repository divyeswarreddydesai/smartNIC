"""Module for TinyDB stat recorder.
"""
# Copyright (c) 2021 Nutanix Inc. All rights reserved.

# Author: sudharshan.dm@nutanix.com

import errno
import os
import time

import tinydb
import portalocker

from .base_stat_recorder import BaseStatRecorder

class TinyDBRecorder(BaseStatRecorder):
  """Recorder that adds stat data into a TinyDB database.
  """
  def __init__(self, dirpath, network_db_filename="network-stats.db.json",
               process_db_filename="process-stats.db.json"):
    """Initializer.

    Args:
      dirpath (str): File path to the database.
      network_db_filename (str): File name for the network stats database.
      process_db_filename (str): File name for the process stats database.
    """
    try:
      os.mkdir(dirpath)
    except OSError as exc:
      if exc.errno == errno.EEXIST:
        pass
      else:
        raise

    self._network_db = tinydb.TinyDB(os.path.join(dirpath, network_db_filename))
    self._process_db = tinydb.TinyDB(os.path.join(dirpath, process_db_filename))
    self._lock_file = os.path.join('/tmp', 'nutest_stats.Lock')

    self._http_table = self._network_db.table("http")
    self._ssh_table = self._network_db.table("ssh")
    self._scp_table = self._network_db.table("scp")

    self._process_table = self._process_db.table("process")

  def add_http_request(self, method, url):
    """Record an HTTP request.

    Args:
      method (str): HTTP method.
      url (str): HTTP URL.

    Returns:
      int: Document ID of the request record.
      None: When document could not be inserted.
    """
    document = {
      "request": {
        "timestamp": time.time(),
        "method": method.upper(),
        "url": url
      }
    }

    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        doc_id = self._http_table.insert(document)
    except portalocker.exceptions.LockException:
      doc_id = None

    return doc_id

  def remove_http_request(self, request_doc_id):
    """Delete an HTTP record.

    Args:
      request_doc_id (int): Document ID of the request record.

    Returns:
      None
    """
    if not request_doc_id:
      return
    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        self._http_table.remove(eids=[request_doc_id])
    except portalocker.exceptions.LockException:
      pass

  def add_http_response(self, request_doc_id, response):
    """Record an HTTP response.

    Args:
      request_doc_id (int): Document ID of the corresponding request record.
      response (requests.Response): HTTP response.

    Returns:
      None.
    """
    if not request_doc_id:
      return
    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        document = self._http_table.get(eid=request_doc_id)
    except portalocker.exceptions.LockException:
      document = {}


    document["response"] = {
      "timestamp": time.time(),
      "status": response.status_code,
      "body_size": len(response.content)
    }

    request = response.request

    document["request"]["url"] = request.url
    document["request"]["num_headers"] = len(request.headers)
    if request.body:
      document["request"]["body_size"] = len(request.body)

    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        self._http_table.update(document, eids=[request_doc_id])
    except portalocker.exceptions.LockException:
      pass

  def add_ssh_command(self, host, command):
    """Record an SSH command execution.

    Args:
      host (str): SSH hostname.
      command (str): SSH command string.

    Returns:
      int: Document ID of the SSH command record.
      None: When document could not be inserted.
    """
    document = {
      "host": host,
      "command": {
        "timestamp": time.time(),
        "string": command
      }
    }

    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        doc_id = self._ssh_table.insert(document)
    except portalocker.exceptions.LockException:
      doc_id = None

    return doc_id

  def add_ssh_result(self, command_doc_id, exit_status, stdout, stderr):
    """Record an SSH commmand execution result.

    Args:
      command_doc_id (int): Document ID of the corresponding SSH command record.
      exit_status (int): Exit status of the SSH command.
      stdout (str): STDOUT data of the SSH command.
      stderr (str): STDERR data of the SSH command.

    Returns:
      None.
    """
    if not command_doc_id:
      return
    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        document = self._ssh_table.get(eid=command_doc_id)
    except portalocker.exceptions.LockException:
      document = {}

    document["result"] = {
      "timestamp": time.time(),
      "status": exit_status,
      "stdout_size": len(stdout),
      "stderr_size": len(stderr)
    }

    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        self._ssh_table.update(document, eids=[command_doc_id])
    except portalocker.exceptions.LockException:
      pass

  def add_inbound_scp_record(self, host, remote_path, local_path):
    """Add an inbound SCP transfer record.

    Args:
      host (str): SCP hostname.
      remote_path (str): File path on the remote host to transfer from.
      local_path (str): File path on the local host to transfer to.

    Returns:
      int: Document ID of the SCP transfer record.
      None: When document could not be inserted.
    """
    document = {
      "host": host,
      "transfer": {
        "remote_path": remote_path,
        "local_path": local_path,
        "timestamp": time.time()
      },
      "type": "INBOUND",
    }

    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        doc_id = self._scp_table.insert(document)
    except portalocker.exceptions.LockException:
      doc_id = None

    return doc_id

  def add_outbound_scp_record(self, host, local_path, remote_path):
    """Add an outbound SCP transfer record.

    Args:
      host (str): SCP hostname.
      local_path (str): File path on the local host to transfer from.
      remote_path (str): File path on the remote host to transfer to.

    Returns:
      int: Document ID of the SCP transfer record.
      None: When document could not be inserted.
    """
    document = {
      "host": host,
      "transfer": {
        "local_path": local_path,
        "remote_path": remote_path,
        "timestamp": time.time()
      },
      "type": "OUTBOUND"
    }

    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        doc_id = self._scp_table.insert(document)
    except portalocker.exceptions.LockException:
      doc_id = None

    return doc_id

  def add_scp_result(self, scp_doc_id):
    """Add an SCP transfer result.

    Args:
      scp_doc_id (int): Document ID of the corresponding SCP transfer record.

    Returns:
      None
    """
    if not scp_doc_id:
      return
    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        document = self._scp_table.get(eid=scp_doc_id)
    except portalocker.exceptions.LockException:
      document = {}

    document["result"] = {
      "timestamp": time.time()
    }

    try:
      with portalocker.Lock(self._lock_file, timeout=60) as _:
        self._scp_table.update(document, eids=[scp_doc_id])
    except portalocker.exceptions.LockException:
      pass

  def add_process_record(self, process):
    """Add a process record.

    Args:
      process (psutil.Process): The process to add stats of.
    """
    document = {
      "timestamp": time.time(),
      "pid": process.pid,
      "ppid": process.ppid(),
      "cpu": {
        "percent": process.cpu_percent()
      },
      "memory": {
        "rss": process.memory_info().rss
      }
    }

    self._process_table.insert(document)
