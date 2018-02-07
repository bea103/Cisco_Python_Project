#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import ipaddress
import re
import collections
import paramiko

# Device class will store all information about devices on our network
class Device (object):

    hw_version = ""
    os_version = ""
    management_ip_address = ""
    password = ""
    management_ip =""
    modules = list()
    neighbors = list()

    # The class "constructor" - It's actually an initializer
    def __init__(self, hw_version, os_version, management_ip_address, password):
        self.hw_version = hw_version
        self.os_version = os_version
        self.management_ip_address = management_ip_address
        self.password = password


def getnetwaddress():

    """
        Open the file to get the IP range assuming format A.B.C.D /8,12,etc
    """
    try:
        addresses = list() #list of all available IPs
        with open('iprange.txt', 'r') as fil:
            for ip_add in fil:
                ip_add = re.search(r'[^\r ^\n]*', unicode(ip_add, "utf-8"))
                ip_add = ipaddress.ip_network(ip_add.group())
                broadcast_address = ip_add.broadcast_address
                proc = subprocess.Popen("ping -c 2 -b " + str(broadcast_address), stdout=subprocess.PIPE, shell=True)
                (out,err) = proc.communicate()
                for line in out.splitlines():
                    matches = re.search(r'^\d+ bytes from (?P<IP>.*): icmp_req=\d ttl=\d+ time=.*$', line, re.MULTILINE)
                    if matches:
                        addresses.append(matches.group('IP'))

        iplist = [item for item, count in collections.Counter(addresses).items() if count == 1] #We delete repeated values due to the two pings

        return iplist
    except IOError:
        print "The file with the IP range doesn't exist"
    except ValueError:
        print "IP range not valid"


def scandpassword():
    iplist = getnetwaddress()
    regex_hw_version = r"Hardware\s*revision\s*(?P<hw_version>\d*\.\d*)"
    regex_os_version = r"IOS.*Version\s*(?P<os_version>\d*\.\d*)"
    #to do regex_modules =
    #regex_neighbors = ""

    passwords = list()  #List with all possible passwords read in password file
    with open('password.txt', 'r') as passwo:
        for line in passwo:
            passwords.append(line.replace("\r\n", ""))
    passwordss = list()
    devices = list()
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for address in iplist:
        for pas in passwords: #Trying all passwords of the list
            try:
                print "Trying connection with device " + address + " password " + pas
                ssh_client.connect(hostname=address,
                                   username='admin',
                                   password=pas)
                passwordss.append([address, pas])
                new_device = Device() #If we stablish a connection we will create a new network device
                new_device.password = pas #We do know now the password of this device

                command = 'show diag' # The aim of this command is finding the hardware version
                (stdout, stderr) = ssh_client.exec_command(command)
                for line in stdout.readlines():
                    for match in re.finditer(regex_hw_version, line, re.MULTILINE):  # We apply the regex in every line
                        new_device.hw_version = match.group('hw_version')

                command = 'show version'  # The aim of this command is finding the os version
                (stdout, stderr) = ssh_client.exec_command(command)
                for line in stdout.readlines():
                    for match in re.finditer(regex_os_version, line, re.MULTILINE):  # We apply the regex in every line
                        new_device.os_version = match.group('os_version')

                #to do
                #command = 'show module'  # The aim of this command is finding the os version
                #(stdout, stderr) = ssh_client.exec_command(command)
                #for line in stdout.readlines():
                #    for match in re.finditer(regex_os_version, line, re.MULTILINE):  # We apply the regex in every line
                #        new_device.os_version = match.group('os_version')
                #
                #command = 'show cdp neighbors'  # The aim of this command is finding the os version
                #(stdout, stderr) = ssh_client.exec_command(command)
                #for line in stdout.readlines():
                 #   for match in re.finditer(regex_neighbors, line, re.MULTILINE):  # We apply the regex in every line
                  #      new_device.os_version = match.group('os_version')

                print "Success"
            except Exception as e:
                print "Fail"
                continue
    for i in passwordss:
        print i[0]+":"+i[1]
    return passwordss

#def print_topology(Device[]): La idea es crear una funcion que reciba una lista de dispositivos e imprima topología

""""
    Bea, la función scandpassword hace el ping y devuelve una lista de dos dimensiones tal que [host contraseña]
"""

scandpassword()
