"""
#! /usr/bin/env python
#
# Copyright (c) 2014 Nutanix Inc. All rights reserved.
#
# Author: manan.shah@nutanix.com
#
# This is the script we use to interact and retrieve information from
# the kmip server.It's similar to kmip_server_utils.py but we can use
# this as independent script to be used on the cluster irrespective of agave or
# nutest.
# NOTE - DO NOT IMPORT THIS AS A MODULE EVER.
"""
# pylint: disable = no-member
# pylint: disable = import-error
# pylint: disable = no-self-use
# pylint: disable = too-many-locals
# pylint: disable = unused-variable
# pylint: disable = unused-import
# pylint: disable = dangerous-default-value
# pylint: disable = no-name-in-module
# pylint: disable = superfluous-parens
# pylint: disable = invalid-name

# nulint: disable=ExceptionTypeValidator
import os
from optparse import OptionParser
import sys
import pexpect


class KmipServer(object):
  """
  Utility class for a KMIP server.
  """

  def __init__(self, ip, username="admin", password="nutanix/4u"):
    """

    Args:
      ip (str): KMS IP
      username (str): username
      password (str): password
    """
    self.kmip_ip = ip
    self.user = username
    self.passw = password

    # Proceed only if login to this kmip works.
    login = 'ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 ' + self.user +\
            '@' + self.kmip_ip
    print(("Login cmd: %s and password: %s" % (login, self.passw)))

    child = pexpect.spawn(login, timeout=20)
    index = child.expect(["password:", pexpect.TIMEOUT])
    if index == 0:
      # KMIP is ping reachable.
      print((child.before))
      child.sendline(self.passw)
      print((child.after))

      i2 = child.expect(["#", "Permission denied", pexpect.TIMEOUT])
      print((child.after))
      child.close() # Don't need the child further.

      if i2 == 0:
        print(("Password is correct. Login to %s Successful" % self.kmip_ip))
      elif i2 == 1:
        print(("Got Permission denied to login to KMIP %s with password %s" %
              (self.kmip_ip, self.passw)))
        sys.exit(-1)
      elif i2 == 2:
        print(("Got a timeout while connecting to KMIP %s" % self.kmip_ip))
        sys.exit(-1)
    elif index == 1:
      print(("Failed to SSH to KMIP %s" % self.kmip_ip))
      sys.exit(-1)

  def get_ca_contents(self, ca_name):
    """Get the raw contents of CA for the input ca name.

    This will return the contents of local CA from the KMIP server.

    TODO : Currently we take ca_name from the user.
           Later we want to dynamically fetch this from the KMIP and
           return a map of CA name and certs.

    Args:
      ca_name (str): CA name on which the KMS is configured.

    Returns:
      Returns the content of CA.
    """

    # Do a quick login here since we have already made sure that
    # ssh access to kmip is fine.

    login = 'ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 '+self.user+'@'+\
            self.kmip_ip
    print(("Login cmd: %s and password: %s" % (login, self.passw)))
    child = pexpect.spawn(login)
    child.expect("password:")
    child.sendline(self.passw)
    child.expect("#")

    # Login OK. Now fetch CA contents.
    child.sendline("show local ca "+ ca_name)
    index = child.expect(["-----BEGIN.*END CERTIFICATE-----", "Error.*"])
    if index == 0:
      print(("Found a CA with name : %s" % ca_name))
      ca_data = child.after
      print(ca_data)
      child.close()
      return ca_data
    elif index == 1:
      print((child.before))
      print((child.after))
      print("Found no CA with name : %s" % ca_name)

  def get_signed_csr(self, csrs, ca_name, duration="365"):
    """Get a CSR signed from the KMS.

    This will return a Digital Cert (Signed CSR ) from the KMIP server.
    Duration field means how long you want the digital certificate to be
    valid for.
    The input CSR can be read from the file path and supplied to this method
    to get it signed and written into a file as under :

    Args:
      csrs (str): file contents of the csr.
      ca_name (str): ca with which you want to get stuff signed.
      duration (str): duration the singed csr should be valid for.

    Returns:
      Contents of the signed csr ie a digital certificate.
    """

    # Do a quick login here since we have already made sure that
    # ssh access to kmip is fine.
    print(("Requesting digital certificate for CSR:\n%s" % csrs))
    login = 'ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 ' + self.user + \
            '@' + self.kmip_ip
    print(("Login cmd: %s and password: %s" % (login, self.passw)))
    child = pexpect.spawn(login)
    child.expect("password:")
    child.sendline(self.passw)
    child.expect("#")

    # Login OK. Now get csr signed.
    child.sendline("config")
    child.expect(".*config.*")
    child.sendline("sign request")
    child.expect("Enter the.*")
    print((child.before))
    print((child.after))
    child.sendline(ca_name)
    child.sendline("2") # 2 - Client CSR
    child.expect("Enter a.*")
    child.sendline(duration) # Certificate validity duration
    print((child.before))
    print((child.after))
    child.expect("Please perform.*")
    child.sendline(csrs)
    child.sendline("\n\n")
    index = child.expect(["-----BEGIN CERTIFICATE-----.*CATE-----", "Error.*"])
    if index == 0:
      # CSR signed successfully
      print((child.before))
      signed_csr = child.after
      child.close()
      return signed_csr
    elif index == 1:
      print((child.before))
      print((child.after))
      print("Error happened while getting the CSR signed")
      sys.exit(-1)

def options():
  """
  Help menu.

  Returns:
    options (object): Options
  """
  usage = "usage: %prog [options] arg"
  parser = OptionParser(usage)

  parser.add_option("--file", dest="csrs",
                    help="Zip file having csrs or a single csr file")
  parser.add_option("--ip", dest="kms_ip",
                    help="Key management server ip")
  parser.add_option("--username", dest="username", default="admin",
                    help="Key management server username. Default = admin")
  parser.add_option("--password", dest="password", default="nutanix/4u",
                    help="Key management server password. Default = nutanix/4u")
  parser.add_option("--ca", dest="ca_name",
                    help="Certificate Authority name for the KMS")
  parser.add_option("--op_cert", dest="output_cert",
                    help="If using individual CSR, mention"
                    " the output file name")
  parser.add_option("-d", action="store_true", default=False,
                    dest="use_defaults",
                    help="Use default hw kms details to sign")

  (opts, args) = parser.parse_args()

  if opts.csrs is None:
    print("\nError: Zip file containing csrs or a csr file is required.\n")
    parser.print_help()
    sys.exit(-1)

  if "zip" not in opts.csrs:
    # Single file supplied
    if opts.output_cert is None:
      print("\nError: Output file must be mentioned for single CSR files.\n")
      parser.print_help()
      sys.exit(-1)

  if not opts.use_defaults:
    if opts.kms_ip is None or opts.ca_name is None:
      print("\nError: CA name and KMS ip are required.\n")
      parser.print_help()
      sys.exit(-1)

  return opts

if __name__ == '__main__':

  options = options()
  csr_file = options.csrs
  ca = options.ca_name
  kmip_ip = options.kms_ip
  user = options.username
  passw = options.password

  if options.use_defaults:
    kmip_ip = "10.1.133.3"
    ca = "nutanix_local_ca"
    print(("Using KMIP IP : %s" % kmip_ip))
    print(("Using CA name : %s" % ca))

  kmip = KmipServer(kmip_ip, user, passw)

  # For handling zip files.
  if 'zip' in csr_file:
    op_dir = "/home/nutanix/unsigned_csrs"
    if os.path.isdir(op_dir):
      print(("Removing old %s" % op_dir))
      os.system("rm -rf " + op_dir)

    # Removing existing signed_csrs.zip.
    sign_dir = "/home/nutanix/signed_csrs.zip"
    if os.path.isdir(sign_dir):
      print(("Removing old %s" % sign_dir))
      os.system("rm -rf " + sign_dir)

    # Unzip the csrs.
    print("Unzipping in unsigned_csrs.")
    cmd = "unzip -od "+op_dir+" "+csr_file
    if os.system(cmd) != 0:
      print("Error in unzipping.")
      sys.exit(-1)

    # Read each file one by one and then get it signed.
    for csr_file in os.listdir(op_dir):
      print(("Getting %s signed." % csr_file))
      csr_file_path = op_dir+'/'+csr_file
      with open(csr_file_path, "r") as fp:
        csr = fp.read()
      s_csr = kmip.get_signed_csr(csr, ca, "300")
      op_csr_file_path = csr_file + '.crt'
      with open(op_csr_file_path, "w") as fp:
        fp.write(s_csr)

    # Now zip all of them into one.
    print("Zip all the signed certs into one as signed_csrs.zip.")
    cmd = "zip signed_csrs *txt.crt"
    if os.system(cmd) != 0:
      print("Error in zipping.")
      sys.exit(-1)
    # Do a clean up by removing them.
    cmd = "rm -rf *txt.crt; rm -rf %s" % op_dir
    if os.system(cmd) != 0:
      print("Error in cleaning up certs.")
      sys.exit(-1)

    # Exit as the signed certs have been zipped.
    sys.exit(0)

  output_cert = options.output_cert
  with open(csr_file, "r") as fp:
    csr = fp.read()
  s_csr = kmip.get_signed_csr(csr, ca, "300")
  with open(output_cert, "w") as fp:
    fp.write(s_csr)
