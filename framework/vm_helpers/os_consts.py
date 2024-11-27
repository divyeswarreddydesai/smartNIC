# Copyright (c) 2016 Nutanix Inc. All rights reserved
#
# Author: Mohammad Ghazanfar <mohammad.ghazanfar@nutanix.com>
"""
This module contains some constants used by OSs.
"""


class IOTools:
  """
  This class enumerates different IO tools.
  """
  DD = 'dd'
  FIO = 'fio'
  DISK_PERF = 'disk_perf'


class FIOEngines:
  """
  This class enumerates different engines used by the IO tool.
  """

  # Basic read(2) or write(2) IO. lseek(2) is used to position the IO location.
  SYNC = 'sync'

  # Basic pread(2) or pwrite(2) IO. Default on all
  # supported operating systems except for Windows.
  PSYNC = 'psync'

  # Basic readv(2) or writev(2) IO.
  VSUNC = 'vsync'

  # Basic preadv(2) or pwritev(2) IO.
  PVSYNC = 'pvsync'

  # Basic preadv2(2) or pwritev2(2) IO.
  PVSYNC2 = 'pvsync2'

  # Windows native asynchronous IO. Default on Windows.
  WINDOWSAIO = 'windowsaio'

  # File is memory mapped and data copied to/from using memcpy(3).
  MMAP = 'mmap'

  # SCSI generic sg v3 IO. May either be synchronous using the SG_IO ioctl,
  # or if the target is an sg character device we use read(2) and write(2) for
  # asynchronous IO.
  SG = 'sg'

  # Doesn't transfer any data, just pretends to. This is mainly used to
  # exercise FIO itself and for debugging/testing purposes.
  NULL = 'null'

  # The RDMA I/O engine  supports  both  RDMA memory semantics (
  # RDMA_WRITE/RDMA_READ) and channel semantics (Send/Recv) for the InfiniBand,
  # RoCE and iWARP protocols.
  RDMA = 'rdma'

class FIOIOPattern:
  """
  This class enumerates the different IO patterns available for FIO
  """

  # Sequential reads
  READ = 'read'

  # Sequential writes
  WRITE = 'write'

  # Random writes
  RAND_WRITE = 'randwrite'

  # Random reads
  RAND_READ = 'randread'

  # Sequential mixed reads and writes
  READ_WRITE = 'rw'

  # Random mixed reads and writes
  RAND_RW = 'randrw'

  # Mixed trims and writes. Blocks will be trimmed first, then written to.
  TRIM_WRITE = 'trimwrite'

# If new repos are needed they should be placed either on Endor, or
# by contacting #corp-it to add them on the rpm-mirror.corp.nutanix.com.
# After they show up, then this dict can be modified to include them in what
# is downloaded.
# This will also work if the LinuxOperatingSystem object is a UVM so we
# should be able to deprecate the PACKAGES_IN_LOCAL_REPO business. It's been
# left as is for now but a shortcut is added so it likely never be called.
# pylint: disable=line-too-long
YUM_REPO_URLS = {
  "rocky": {
    "8": [
      "https://rpm-mirror.corp.nutanix.com/rocky/Rocky8-AppStream.repo",
      "https://rpm-mirror.corp.nutanix.com/rocky/Rocky8-BaseOS.repo",
      "https://rpm-mirror.corp.nutanix.com/epel/epel8.repo"
    ],
    "9": [
      "https://rpm-mirror.corp.nutanix.com/rocky/Rocky9-rocky.repo",
      "https://rpm-mirror.corp.nutanix.com/epel/epel9.repo"
    ]
  },
  "centos": {
    "7": [
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-Base.repo",
      "https://rpm-mirror.corp.nutanix.com/epel/epel7.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/epel-testing.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/epel.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-CR.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-Debuginfo.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-Media.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-Sources.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-Vault.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-fasttrack.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/CentOS-x86_64-kernel.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/nutanix-cvm-3rdparty.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/nutanix-cvm-test.repo",
      "http://endor.dyn.nutanix.com/nutest/yum_repo_files/centos/7/nutanix-cvm-utility.repo"]
    }
  }
# pylint: enable=line-too-long
