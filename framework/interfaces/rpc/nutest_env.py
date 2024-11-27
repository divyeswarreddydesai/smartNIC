"""
Copyright (c) 2012, 2024 Nutanix Inc. All rights reserved.

Author: cui@nutanix.com, rickard.faith@nutanix.com, sam.gaver@nutanix.com

This module sets up Python path for the rest of infrastructure code.

For the Python 2 to Python 3 transition, look for environment variables
indicating the script should run under a specific version of Python:

  PYTHON_TARGET_VERSION: A version number prefix, such as "3" or "3.9".
  PYTHON_TARGET_PATH: A fully-qualified path to the Python interpreter.
  PY3_VENVS: A comma separated string of virtual environments we want to add
             to our sys.path.

  PY2_PATHS: A comma separated string of paths to python2 libs we want to add
             egg files from.


These variables can be set in the script prior to the "import env"
statement with code similar to this:

  import os
  if os.environ.get("PYTHON_TARGET_VERSION") is None:
    os.environ["PYTHON_TARGET_VERSION"] = "3.9"
  if os.environ.get("PYTHON_TARGET_PATH") is None:
    os.environ["PYTHON_TARGET_PATH"] = "/home/nutanix/bin/venv/bin/python3.9"

"""

# pylint: disable=invalid-name, protected-access
assert __name__ != "__main__", "This module should NOT be executed."

import os
import sys

def cleanup_python_os_vars():
  """
  Remove the env variables for python target version, python target path, and
  python embedded mode that were set up in the parent so that they are not
  accidentally inherited by child processes. Do this unconditionally regardless
  of Python2 or Python3.
  """
  if 'PYTHON_TARGET_VERSION' in os.environ:
    del os.environ['PYTHON_TARGET_VERSION']
  if 'PYTHON_TARGET_PATH' in os.environ:
    del os.environ['PYTHON_TARGET_PATH']

# First, determine if the script should run under a specific Python version:
# if PYTHON_TARGET_VERSION and PYTHON_TARGET_PATH are set, then use those
# values.
python_target_version = os.environ.get("PYTHON_TARGET_VERSION", None)
python_target_path = os.environ.get("PYTHON_TARGET_PATH", None)
py3_venv_paths = os.environ.get("PY3_VENVS", None)
py2_lib_paths = os.environ.get("PY2_PATHS", None)

if python_target_version is not None and python_target_path is not None:
  # Make sure to remove the environment variables that were set in the
  # parent so that they are not accidentally inherited by child processes that
  # still want to use Python 2. Do this if we exec or not.
  cleanup_python_os_vars()
  # Second, determine which version of Python is currently being used.
  python_current_version = ".".join([str(s) for s in sys.version_info[:3]])
  program_path = sys.argv[0]
  # If no script name was passed to the Python interpreter, argv[0] is empty
  # string. This will happen when Python interpreter is run by embedded
  # Python/C api.
  if not program_path:
    print("Cannot determine program path.")
    os._exit(1)

  if (python_current_version.startswith("3") and py3_venv_paths):
    # Start at the end so that we put the most 'important' paths at the
    # beginning. This prevents older components like NCC from tripping us up.
    for venv_path in reversed(py3_venv_paths.split(',')):
      sys.path.insert(0, "%s/lib/python%s/site-packages" %
                      (venv_path, python_target_version))
      sys.path.insert(0, "%s/lib64/python%s/site-packages" %
                      (venv_path, python_target_version))
  # If the current version of Python is different from the specified version of
  # Python or if the version is same but the location to binary is different,
  # then exec the specified version and binary. The check for python target
  # binary should be done only when we are not executing in embedded mode. We
  # compare the python_binary to realpath of python_target_path to avoid issues
  # where python_target_path is a symlink.
  python_binary = os.path.realpath('/proc/%s/exe' % os.getpid())
  if (not python_current_version.startswith(python_target_version) or
      (python_binary.strip() != os.path.realpath(python_target_path))):
    args = [python_target_path] + sys.argv
    rc = os.execve(python_target_path, args, os.environ)
    print("Could not exec: %s %s: %s" % (python_target_path, args,
                                         os.strerror(rc)))
    os._exit(2)

# At this point, the version of Python we are using is either the specified
# version, or there was no specified version. This is where other env.py
# modules could add code to do additional setup.

if sys.version_info[0] == 2 and py2_lib_paths:
  # Parse the py2_lib_paths, find all the files in those lib paths, ensure we
  # don't have duplicates, then add each of the eggs to the sys.path.

  # 'paths' is a dict with keys of egg file and values are the full path to
  # to the egg file.
  from collections import OrderedDict
  paths = OrderedDict()
  for py2_lib_path in py2_lib_paths.split(','):
    if os.path.isdir(py2_lib_path):
      for path in os.listdir(py2_lib_path):
        # Ensure we only have one instance of the egg file.
        paths.setdefault(os.path.basename(path),
                         os.path.join(py2_lib_path, path))
  # Now we have all the eggs, add them to the sys path.
  _ = [sys.path.insert(0, path) for _, path in paths.items()]

# Regardless of Python version, this module does not export any symbols.
__all__ = []
