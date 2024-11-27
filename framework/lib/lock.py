"""
This module defines a locking class which can be used to make only one process
or thread access the file/directory at once. We use the nutest log directory
to store the locks in vs storing them with the file or directory to ensure
a failed test doesn't affect another failed test due to an existing lockfile.
The test logs are recreated per test so this should be safe.

Copyright (c) 2019 Nutanix Inc.
"""
# pylint: disable=unused-argument
# pylint: disable=no-self-use

import errno
import os
import platform
import time
import traceback
from contextlib import contextmanager
import portalocker

from framework.logging.error import ExpError
from framework.logging.log import DEBUG, ERROR


@contextmanager
def lock_file(entity, timeout=300, poll_interval=5, reentrant=False,
              debug=False):
  """
  Acquires the lock to access the entity. Only one lock file can exist at a
  time, and it exists only when a process is owning it. Therefore only one
  process can manipulate the entity object at once.

  We want to store the lock file in the logs dir not on the actual entity.
  For instance if the entity is /tmp/file.txt, the lock file would be:
    /home/stgaver/nutest/logs/locks/tmp/file.txt/LOCKFILE
  If the entity is /tmp/dir/, the lock file would be:
    /home/stgaver/nutest/logs/locks/tmp/dir/LOCKFILE
  This allows for multiple locks to be used at runtime with directories
  with the same name or files with the same name but different absolute
  paths.

  Args:
    entity (str): This could be a dir path, filename, or absolute filename.
    timeout (int): How long to wait for lock. Default: 300s.
    poll_interval (int): How often to poll for a released lock. Default: 5s.
    reentrant (bool): If we should use a reentrant.
    debug (bool): If we should print out debug info. Off by default to prevent
      excessive logging for every ssh call.

  Raises:
    NuTestTimeoutError: If we specified a timeout and the process didn't get
      the lock within that timeout.
  """
  # Where to store all the locks. We'll use /tmp/ to ensure we are using local
  # storage for the locks vs a possible NFS location (JITA testers). We've seen
  # long delays in lock acquisition when running on the JITA /logs dir.
  lock_base_dir = os.path.join("/tmp/",
                               os.environ.get("_NUTEST_RUN_ID",
                                              "NUTEST_DEFAULT_TEST_CASE"),
                               "locks") if not platform.system() == 'Darwin'\
                  else os.path.join(os.environ.get("NUTEST_LOGDIR"), "locks")

  entity = entity.lstrip('/')
  lock_dir = os.path.join(lock_base_dir, entity)
  safe_mkdirs(lock_dir)
  lock_fn = os.path.join(lock_dir, "LOCKFILE")
  pid = os.getpid()
  start_time = time.time()
  try:
    my_lock = portalocker.Lock if not reentrant else portalocker.RLock
    with my_lock(lock_fn, 'w', timeout=timeout, check_interval=poll_interval):
      if debug:
        DEBUG("PID-{}: Lock on {} acquired after {:.3f}s, timeout: {}s".\
          format(pid, lock_fn, time.time() - start_time, timeout))
        acquire_time = time.time()
      yield
    if debug:
      DEBUG("PID-{}: Lock on {} released after being held for {:.3f}s"
            .format(pid, lock_fn, time.time() - acquire_time))
  except portalocker.exceptions.LockException as ex:
    if "Resource temporarily unavailable" in str(ex):
      raise ExpError(
        "Timed out getting lock after {}s, PID-{}, Lock: {}"
        .format(time.time() - start_time, pid, lock_fn))
    raise ex


def safe_mkdirs(path):
  """
  Safely make the path. Normal makedirs has a race between checking for a
  path existing and actually making the path.

  Args:
    path (str): Path to make.

  Raises:
    OSError: If makedirs failed and reason wasn't already exists.
  """
  if not os.path.exists(path):
    try:
      os.makedirs(path)
    except OSError as exc:
      if exc.errno != errno.EEXIST:
        ERROR("Failed to create {}: {}".format(path, traceback.format_exc()))
        raise exc
      DEBUG("Ignoring makedirs failure, path {} exists".format(path))
