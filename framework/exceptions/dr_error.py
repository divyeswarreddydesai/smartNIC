#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: sandeep.ghadage@nutanix.com

"""This module defines DR base exception."""

import os
import json
from framework.exceptions.nutest_error import NuTestError
from framework.entities.protection_domain.protection_domain import \
  ProtectionDomain
from framework.entities.remote_site.remote_site import RemoteSite


class DrError(NuTestError):
  """Class for DR based exceptions.
  """

  def __init__(self, cluster_list=None):
    """Constructor for the base framework exception.

    Args:
      cluster_list(list): List of cluster instances.
    """

    # Collect the entity based logs.
    outfile = open(os.environ['NUTEST_LOGDIR']+'/status_of_clusters.log', 'w+')
    for cluster in cluster_list:
      # Listing PDs in log file.
      pd_list = [pd.get() for pd in
                 ProtectionDomain(cluster=cluster).list(cluster=cluster)]
      outfile.write("--------------------------------------------------\n")
      outfile.write("List of PDs in cluster %s.\n" % cluster.name)
      outfile.write("--------------------------------------------------\n")
      for pd_info in pd_list:
        line = json.dumps(pd_info, indent=4)
        outfile.write(line+"\n\n")
        outfile.write("====================================================\n")

      # Listing Remote Sites in log file.
      # pylint: disable=unnecessary-comprehension
      rs_list = [rs for rs in
                 RemoteSite(cluster=cluster).list(cluster=cluster)]
      # pylint: enable=unnecessary-comprehension
      outfile.write("\n\n--------------------------------------------------\n")
      outfile.write("List of Remote Site in cluster %s.\n" % cluster.name)
      outfile.write("--------------------------------------------------\n")
      for rs in rs_list:
        line = json.dumps(rs.get(), indent=4)
        outfile.write(line+"\n\n")
        outfile.write("==================================================\n")

      # Listing Remote Site Snapshots in log file.
      for rs in rs_list:
        outfile.write("\n\n------------------------------------------------\n")
        outfile.write("List of Snapshot from %s to Remote Site %s.\n" %
                      (cluster.name, rs.name))
        outfile.write("--------------------------------------------------\n")
        for snapshot in rs.get_snapshots():
          line = json.dumps(snapshot, indent=4)
          outfile.write(line+"\n\n")
          outfile.write("==================================================\n")

    outfile.close()
    super(DrError, self).__init__(self)
