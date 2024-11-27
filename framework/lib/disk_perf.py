#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: sumanth.ananthu@nutanix.com
# Taken references from patrick's agave code to get the usage of disk perf
# command
#
# This class provides a wrapper around the disk perf tool for setting
# parameters and constructing the command string.
#
# Example: you can execute this file individually which does following things
# vm.get_disk_perf_path is set to "/home/nutanix/bin/disk_perf" manually for
# testing purpose
#
# We create a DiskPerfCommand object, set the target, and store the
# string. We then set random and target to new values and store the
# new string.  Finally we print the two strings we stored.
#
#   cmd = DiskPerfCommandGenerator()
#   cmd.target = "/dev/sdb"
#   string1 = cmd.generate_command()
#   print string1
#   cmd.target = "/dev/sdc"
#   cmd.random = True
#   string2 = cmd.generate_command()
#   print string2
#
# Output of example:
#   /home/nutanix/bin/disk_perf -bs=1048576 -count=1024 -inflight=32
#   -o_direct=true -random=false -random_seed=1 -input_buffer_source=
#   -num_workloads=-1 -oseek=0  -of=/dev/sdb -repeat_writes=false
#   -repeat_write_skip_size=1048576 -repeat_write_start_offset=0
#   -maximum_seek=8388608 -stats_interval_msecs=1000
#
#   /home/nutanix/bin/disk_perf -bs=1048576 -count=1024 -inflight=32
#   -o_direct=true -random=true -random_seed=1 -input_buffer_source=
#   -num_workloads=-1 -oseek=0 -of=/dev/sdc -repeat_writes=false
#   -repeat_write_skip_size=1048576 -repeat_write_start_offset=0
#   -maximum_seek=8388608 -stats_interval_msecs=1000

__all__ = ["DiskPerfCommandGenerator"]

import io
from framework.logging.log import ERROR

class DiskPerfCommandGenerator(object):
  def __init__(self, **kwargs):
    """
    Initialize dictionary of disk perf parameters.
    """
    # Target file or device to perform reads or writes.
    self._target = kwargs.get('target', None)

    # The block size to be used for reading/writing.
    self._block_size = kwargs.get('block_size', 1024**2)

    # The number of blocks to process per workload. If < 0, then all the
    # blocks starting from seek offset to the end of the relevant files are
    # processed
    self._count = kwargs.get('count', 1024)

    # The total number of inflight async IO requests used by each workload.
    # Only relevant when o_direct is used.
    self._inflight = kwargs.get('inflight', 32)

    # Whether or not to use O_DIRECT to read/write data.
    self._o_direct = kwargs.get('o_direct', True)

    # Percentage of random IOs. The chance that an offset for the next IO
    # will be chosen randomly.) default: 0
    self._random_pct = kwargs.get('random_pct', 0)

    # Whether the IO is to be read randomly. If true, count is expected to be
    # >= 0.
    if self._random_pct > 0:
      self._random = False
    else:
      self._random = kwargs.get('random', True)

    # If >= 0, use this to derive the seed of the random number generator.
    self._random_seed = kwargs.get('random_seed', 1)

    # Input file from which data will be read into input buffers. If specified,
    # the data buffer used for writes will be filled with this content instead
    # of random bytes.
    self._input_buffer_source = kwargs.get('input_buffer_source', "")

    # Explicit specification of the number of workloads if > 0. Otherwise,
    # the number of workloads are derived from the number of comma separated
    # values given to --if and --of.
    self._num_workloads = kwargs.get('num_workloads', -1)

    # For sequential IO, this specifies the initial seek offset from where the
    # read or write begins.
    self._seek = kwargs.get('oseek', 0)

    # Whether or not to write.
    self._write = kwargs.get('write', True)

    # Whether or not to have multiple runs.
    self._repeat_writes = kwargs.get('repeat_writes', False)

    # Bytes to step/skip in repeat write mode.
    self._repeat_write_skip_size = kwargs.get('repeat_write_skip_size', \
                                               1024**2)

    # Offset to start in case of repeated write mode
    self._repeat_write_start_offset = kwargs.get('repeat_write_start_offset', \
                                                  self._seek)

    # The max offset to seek.
    self._maximum_seek = kwargs.get('maximum_seek', \
                                     8*self._repeat_write_skip_size)

    # Maximum seconds for which the command should be run.
    self._time_limit_secs = kwargs.get('time_limit_secs', 0)

    # Default dump progress collector interval.
    self._stats_interval_msecs = kwargs.get('stats_interval_msecs', 1000)

    # Default disk_perf path.
    self._disk_perf_path = kwargs.get('disk_perf_path',
                                      "/home/nutanix/bin/disk_perf")

    # Input file from which data will be read.
    self._input_file = kwargs.get('input_file', None)

  @property
  def block_size(self):
    """getter method for block_size
    """
    return self._block_size

  @property
  def count(self):
    """getter method for count
    """
    return self._count

  @property
  def inflight(self):
    """getter method for inflight
    """
    return self._inflight

  @property
  def input_buffer_source(self):
    """getter method for input_buffer_source
    """
    return self._input_buffer_source

  @property
  def num_workloads(self):
    """getter method for num_workloads
    """
    return self._num_workloads

  @property
  def o_direct(self):
    """getter method for o_direct
    """
    return self._o_direct

  @property
  def random_pct(self):
    """getter method for random_pct
    """
    return self._random_pct

  @property
  def random(self):
    """getter method for random
    """
    return self._random

  @property
  def random_seed(self):
    """getter method for random_seed
    """
    return self._random_seed

  @property
  def seek(self):
    """getter method for seek
    """
    return self._seek

  @property
  def maximum_seek(self):
    """getter method for maximum_seek
    """
    return self._maximum_seek

  @property
  def repeat_write_skip_size(self):
    """getter method for repeat_write_skip_size
    """
    return self._repeat_write_skip_size

  @property
  def repeat_writes(self):
    """getter method for repeat_writes
    """
    return self._repeat_writes

  @property
  def repeat_write_start_offset(self):
    """getter method for repeat_write_start_offset
    """
    return self._repeat_write_start_offset

  @property
  def target(self):
    """getter method for target location for disk_perf
    """
    return self._target

  @property
  def write(self):
    """getter method for write
    """
    return self._write

  @property
  def time_limit_secs(self):
    """getter method for time_limit_secs
    """
    return self._time_limit_secs

  @property
  def stats_interval_msecs(self):
    """getter method for stats_interval_mses
    """
    return self._stats_interval_msecs

  @property
  def input_file(self):
    """getter method for input_file
    """
    return self._input_file

  @repeat_writes.setter
  def repeat_writes(self, repeat_writes):
    """Set the flag to allow repeated writes at fixed offsets.
    """
    self._repeat_writes = repeat_writes

  @repeat_write_skip_size.setter
  def repeat_write_skip_size(self, repeat_write_skip_size):
    """Set the step size to seek when repeat_writes is set.
    """
    self._repeat_write_skip_size = repeat_write_skip_size

  @repeat_write_start_offset.setter
  def repeat_write_start_offset(self, repeat_write_start_offset):
    """Set the start offset when repeat_writes is set.
    """
    self._repeat_write_start_offset = repeat_write_start_offset

  @maximum_seek.setter
  def maximum_seek(self, maximum_seek):
    """Set the max offset to seek when multiple runs is set.
    """
    self._maximum_seek = maximum_seek

  @block_size.setter
  def block_size(self, block_size):
    """Set the block size to be used for reading/writing.
    """
    self._block_size = block_size

  @count.setter
  def count(self, count):
    """Set the number of blocks to process per workload. If < 0, then all the
    blocks starting from seek offset to the end of the relevant files are
    processed.
    """
    self._count = count

  @inflight.setter
  def inflight(self, inflight):
    """Set the total number of inflight async IO requests used by each
    workload. Only relevant when o_direct is used.
    """
    self._inflight = inflight

  @input_buffer_source.setter
  def input_buffer_source(self, input_buffer_source):
    """Set the input file from which data will be read into input buffers.
    """
    self._input_buffer_source = input_buffer_source

  @num_workloads.setter
  def num_workloads(self, num_workloads):
    """Set the number of workloads.
    """
    self._num_workloads = num_workloads

  @o_direct.setter
  def o_direct(self, o_direct):
    """Set whether or not to use O_DIRECT to read/write data.
    self._o_direct = o_direct
    """

  @random_pct.setter
  def random_pct(self, random_pct):
    """
    Set the percentage of random IOs generated.
    """
    self._random_pct = random_pct

  @random.setter
  def random(self, random):
    """Set whether the IO is to be read randomly. If true, count is expected
    to be >= 0.
    """
    self._random = random

  @random_seed.setter
  def random_seed(self, random_seed):
    """Set the seed of the random number generator.
    """
    self._random_seed = random_seed

  @seek.setter
  def seek(self, seek):
    """Set the initial seek offset from where the read or write begins for
    sequential I/O.
    """
    self._seek = seek

  @target.setter
  def target(self, target):
    """Set target file or device to perform reads or writes.
    """
    self._target = target

  @write.setter
  def write(self, write):
    """Set whether or not to write.
    """
    self._write = write

  @time_limit_secs.setter
  def time_limit_secs(self, time_limit_secs):
    """Set the time limit in seconds for which the command should be run.
    """
    self._time_limit_secs = time_limit_secs

  @stats_interval_msecs.setter
  def stats_interval_msecs(self, stats_interval_msecs):
    """set the stats interval in msecs for which command should be run
    """
    self._stats_interval_msecs = stats_interval_msecs

  @input_file.setter
  def input_file(self, input_file):
    """set the input file for which command should be run
    """
    self._input_file = input_file

  def generate_command(self):
    """Constructs and returns the command string.

    Args:
      vm object through which path of disk_perf binary can be known

    Returns:
      Command string for disk perf. returns None if target is not set
    """
    if not self._target:
      ERROR("Must set target")
      return None
    cmd_buf = io.StringIO()
    cmd_buf.write("%s " % self._disk_perf_path)
    cmd_buf.write("-bs=%d " % self._block_size)
    cmd_buf.write("-count=%d " % self._count)
    cmd_buf.write("-inflight=%d " % self._inflight)
    cmd_buf.write("-o_direct=true " if self._o_direct else
                  "-o_direct=false ")
    cmd_buf.write("-random=true " if self._random else "-random=false ")
    cmd_buf.write("-random_seed=%d " % self._random_seed)
    if self._write and self._input_buffer_source != "":
      cmd_buf.write("-input_buffer_source=%s " % self._input_buffer_source)
    cmd_buf.write("-num_workloads=%s " % self._num_workloads)
    cmd_buf.write("-oseek=%s " % self._seek if self._write else
                  "-iseek=%s " % self._seek)
    cmd_buf.write("-of=%s " % self._target if self._write else
                  "-if=%s " % self._target)
    cmd_buf.write("-repeat_writes=true " if self._repeat_writes else
                  "-repeat_writes=false ")
    cmd_buf.write("-repeat_write_skip_size=%s " %self._repeat_write_skip_size)
    cmd_buf.write("-repeat_write_start_offset=%s "
                  % self._repeat_write_start_offset)
    cmd_buf.write("-maximum_seek=%s " %self._maximum_seek)
    if self._time_limit_secs > 0:
      cmd_buf.write("-time_limit_secs=%d " % self._time_limit_secs)
    cmd_buf.write("-stats_interval_msecs=%s "
                  % self._stats_interval_msecs)
    if self._random_pct > 0:
      cmd_buf.write("-random_pct=%d" % self._random_pct)
    if self._input_file:
      cmd_buf.write("-if=%s" % self._input_file)
    return cmd_buf.getvalue()

if __name__ == "__main__":
  cmd = DiskPerfCommandGenerator()
  cmd.target = "/dev/sdb"
  cmd.input_file = "/dev/zero"
  string1 = cmd.generate_command()
  print(string1)
  cmd.target = "/dev/sdc"
  cmd.random = True
  string2 = cmd.generate_command()
  print(string2)
