#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os.path
import subprocess
import ipaddress
import re
import collections
import paramiko
import networkx as nx
import matplotlib.pyplot as plt
import Tkinter as tk
import csv
import urllib2
import json
import time

# Device class will store all information about devices on our network
class Device (object):

    hw_version = ""
    os_version = ""
    model = ""
    management_ip_address = ""
    password = ""
    ip = ""
    hostname = ""
    serialNumber = ""
    EOX = ""
    modules = list()
    neighbors_id = list() # identity of every neighbor
    if_to_neighbor = list() # interface to access neighbors (if_to_neighbor[0] to access neighbors_id[0])
    if_to_neighbor_diagram = list() #Name that will be paint at topology
    if_description = list() #Interface description
    if_status = list()#Interface status
    if_name = list()#Interface name
    if_line_protocol = list()#Interface line protocol status


def getNetwAddress():

    """
        Open the file to get the IP range assuming format A.B.C.D /8,12,etc also starts a broadcast ping for all the broadcast addresses associated with the 
        network addresses in the IP range file. 
    """
    global iprangePath #Path to file

    try:
        addresses = list() #list of all available IPs
        with open('iprange.txt', 'r') as fil:
            for lin in fil:
                lin=lin.replace(" ","")
                lin=lin.split(",")
                for ip_add in lin:
                    ip_add = ipaddress.ip_network(unicode(ip_add, "utf-8"))
                    broadcast_address = ip_add.broadcast_address
                    proc = subprocess.Popen("ping -c 4 -b " + str(broadcast_address), stdout=subprocess.PIPE, shell=True)
                    (out,err) = proc.communicate()
                    for line in out.splitlines():
                        matches = re.search(r'^\d+ bytes from (?P<IP>.*): (icmp_req=\d|icmp_seq=\d) ttl=\d+ time=.*$', line, re.MULTILINE)
                        if matches:
                            addresses.append(matches.group('IP'))
        iplist = [item for item, count in collections.Counter(addresses).items() if count >= 1] #We delete repeated values due to the two pings                 
    except IOError:
        print "The file with the IP range doesn't exist"
    except ValueError:
        print "IP range not valid"
    return iplist


def scandPassword():

    """
        This function is the one that searches for avaiable devices in the networks in iplist, tries all the passwords in each IP avaiable and return a list of
        every device with it's password. 
    """

    global passwordPath #Path to file
    iplist = getNetwAddress()

    passwords = list()  #List with all possible passwords read in password file
    with open(passwordPath, 'r') as passwo:
        for line in passwo:
            passwords.append(line.replace("\r\n", ""))
    passwordss = list()
    devices = list()
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for address in iplist:
        for pas in passwords: #Trying all passwords of the list
            try:
                ssh_client.connect(hostname=address,
                                   username='admin', #User it's supposed to be named admin, with privilege 15. 
                                   password=pas)
                passwordss.append([address, pas])
            except Exception as e:
                continue
    print
    return passwordss

def getValues():
    
    #Esta función llama a la anterior para obtener una lista de
    #ips activas y sus contraseñas asociadas
    regex_hw_version = r"Hardware\s*(?:r|R)evision\s+:?\s*(?P<hw_version>\d*\.\d*)"
    regex_os_version = r"IOS.*Version\s*(?P<os_version>\d*\.\d*\(\d*\w*\))"
    regex_model = r"(?P<model>Cisco \w* \(\w*\))"
    regex_modules = r"DESCR:\s.(?P<modules>.*)."
    regex_neighbors_device = r"Device ID: (?P<device_id>.*)$" #RegEx for Device ID
    regex_neighbors_int = r"((Interface: (?P<interface>(?P<if_name>[FGS]\w*)(?P<slot>(\/\d){0,2}))))" #RegEx for the interface
    regex_hostname = r"hostname\s+(?P<host_name>\w.*)"
    regex_domain = r"(ip domain name |ip domain-name )(?P<domain>.*)"
    regex_interface_status =  r"(?P<if_name>(Fast|Giga|Ser)\w.*(\d*\/){0,2})( is (?P<status>\w.*), line protocol is (?P<line_protocol>\w.*))"
    regex_description = r"Description: (?P<description>\w.*)"
    regex_serialNumber=r"Chassis\s+Serial\s+Number\s+:\s+(?P<serialNumber>\w+)"
    dic = {'R': 'Router', 'T': 'Trans Bridge', 'B': 'Source Route Bridge', 'S': 'Switch', 'H': 'Host', 'I': 'IGMP',
           'r': 'repeater'}  # Dic for show cdp neighbors command

    devices = scandPassword() # devices contains all the devices which the connection was successful (address, password)

    #List for all devices
    device_list = []

    for i in devices:

        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])

        new_device = Device() #If we stablish a connection we will create a new network device
        new_device.password = i[1] #We do know now the password of this device
        new_device.ip = i[0] # Device's IP address

        command = 'show version'  # The aim of this command is finding the os version
        stdin, stdout, stderr = ssh_client.exec_command(command)
        for line in stdout.readlines():
            for match in re.finditer(regex_os_version, line, re.MULTILINE):  # We apply the regex in every line
                new_device.os_version = match.group('os_version')
            for match in re.finditer(regex_model, line, re.MULTILINE):  # We apply the regex in every line
                new_device.model = match.group('model')

        ssh_client.close()

        hostname = ""
        host_domain = ""
        
        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])
        command = 'show diag | begin Chassis' # The aim of this command is show the configuration to get the hostname and the domain
        stdin, stdout, stderr= ssh_client.exec_command(command)
            
        for line in stdout.readlines():
            for match in re.finditer(regex_serialNumber, line, re.MULTILINE):  # We apply the regex in every line
                 new_device.serialNumber = match.group('serialNumber')

        ssh_client.close()
        
        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])
        command = 'show running-config | include hostname' # The aim of this command is show the configuration to get the hostname and the domain
        stdin, stdout, stderr= ssh_client.exec_command(command)
        
            
        for line in stdout.readlines():
            
            for match in re.finditer(regex_hostname, line, re.MULTILINE):  # We apply the regex in every line
                hostname = match.group('host_name')

        ssh_client.close()
        
        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])
        command = 'show interfaces | include (up|down|Description)' # The aim of this command is show the interfaces status and description
        stdin, stdout, stderr= ssh_client.exec_command(command)
        
        new_device.if_name = list()
        new_device.if_status = list()
        new_device.if_line_protocol = list()
        new_device.if_description = list()
        position = 0
        description = ""

        for line in stdout.readlines():
            
            #Set to "none" the interface descriotion
            new_device.if_description.append("None") 
            
            for match in re.finditer(regex_interface_status, line, re.MULTILINE):  # We apply the regex in every line    
                
                new_device.if_name.append(match.group('if_name'))
                new_device.if_status.append(match.group('status'))
                new_device.if_line_protocol.append(match.group('line_protocol'))
                position += 1

            
            for match in re.finditer(regex_description, line, re.MULTILINE):  # We apply the regex in every line    
                
                #Override the description
                description = match.group('description')
                new_device.if_description[position] = description[:len(description)-1]
            
        ssh_client.close()
        
        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])
        command = 'show running-config | include (ip domain-name|ip domain name)' # The aim of this command is show the configuration to get the hostname and the domain
        stdin, stdout, stderr= ssh_client.exec_command(command)
        
        host_domain = ""

        for line in stdout.readlines():
            
            for match in re.finditer(regex_domain, line, re.MULTILINE):  # We apply the regex in every line    
                #host_domain = hostname[:len(hostname)-1] + "." + match.group('domain')
                host_domain = match.group('domain')
            
        ssh_client.close()
        
        if host_domain == "":
            host_domain = hostname[:len(hostname)-1]
        else:
            host_domain = hostname[:len(hostname)-1] + "." + host_domain
        new_device.hostname = host_domain
            
        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])
        command = 'show diag' # The aim of this command is finding the hardware version
        stdin, stdout, stderr= ssh_client.exec_command(command)
        for line in stdout.readlines():
            for match in re.finditer(regex_hw_version, line, re.MULTILINE):  # We apply the regex in every line
                new_device.hw_version = match.group('hw_version')
        ssh_client.close()

        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])
        command = 'show inventory'  # The aim of this command is finding all modules
        stdin, stdout, stderr = ssh_client.exec_command(command)
        new_device.modules = list()
        for line in stdout.readlines():
            for match in re.finditer(regex_modules, line, re.MULTILINE):  # We apply the regex in every line
                new_device.modules.append(match.group('modules')) #Appending every module to modules lists...

        ssh_client.close()


        ssh_client.connect(hostname=i[0],
                           username='admin',
                           password=i[1])
        command = 'show cdp neighbors detail | include (Device|Interface)'  # The aim of this command is finding information about neighbors
        
        stdin, stdout, stderr = ssh_client.exec_command(command)
        
        new_device.neighbors_id = list()
        new_device.if_to_neighbor = list()
        new_device.if_to_neighbor_diagram = list()

        for line in stdout.readlines():
           
            for match in re.finditer(regex_neighbors_device, line, re.MULTILINE):  # We apply the regex in every line
                
                new_device.neighbors_id.append(match.group('device_id'))
                
            for match in re.finditer(regex_neighbors_int, line, re.MULTILINE):  # We apply the regex in every line
                new_device.if_to_neighbor.append(match.group('interface'))

            #Convert the interface name to the diagram
            for match in re.finditer(regex_neighbors_int, line, re.MULTILINE):  # We apply the regex in every line
                
                #Auxiliary string
                if_name_aux = ""
                match_aux = match.group('if_name')

                #Check the interface type
                if "FastEthernet" in match.group('if_name'):

                    #Create the name  that will be paint in the diagram (Name+slot)
                    if_name_aux = "Fas" + match_aux[len(match_aux)-1] + match.group('slot')
                
                elif "GigabitEthernet" in match.group('if_name'):
                    if_name_aux = "Gi" +  match_aux[len(match_aux)-1] + match.group('slot')
                
                elif "Serial" in match.group('if_name'):
                    if_name_aux = "Se" + match_aux[len(match_aux)-1] + match.group('slot')
                
                else:
                    if_name_aux = match.group('interface') 
                
                new_device.if_to_neighbor_diagram.append(if_name_aux)

        ssh_client.close()  
        
        print ""
        print "################################################################################"
        print ""
        print "IP: " + new_device.ip
        print "Hostname: " + new_device.hostname
        print "Password: " + new_device.password
        print "Model: " + new_device.model
        print "OS Version: " + new_device.os_version
        print "HW Version: " + new_device.hw_version
        print "Serial Number: " + new_device.serialNumber
        print ""
        print "Modules: "
        print ""
        for i in range (len(new_device.modules)):
            print "    Module " + str(i+1) + ": " + new_device.modules[i][0:len(new_device.modules[i])-1]
        print ""
        
        print "Interfaces status and description:"
        print ""
        for i in range (len(new_device.if_status)):
            print "    Interface: " + new_device.if_name[i] + " Description: " + new_device.if_description[i] + " Status: " + new_device.if_status[i] + " Line Protocol: " + new_device.if_line_protocol[i]
        print ""

        print "Neighbors:"
        print ""
        for i in range(len(new_device.neighbors_id)):
            
            aux_nei = str(new_device.neighbors_id[i])
            
            print "    Neighbor " + str(i+1) + ": " + str(aux_nei[:len(aux_nei)-1]) + " -> via " + new_device.if_to_neighbor[i] + " (" + new_device.if_to_neighbor_diagram[i] + ")"
        
        #Add the device to the list
        device_list.append(new_device);
    return device_list

#Function to print the network topology
def print_topology(device_list):
    
    #Auxiliaries variables
    i = 0
    j = 0
    interfaces = ""

    #List to save the neighbors of a node
    neighbors_id_single_list = list()
    
    #List to save all the neighbors
    neighbors_id_multi_list = list()
    neighbors_interface_list = list()
    repeated_neig_list = list()

    #Looking for repeated neighbors
    for i in range(0,len(device_list)):
        
        repeated_neig_list = list()    
        
        #For each neighbors
        for item in device_list[i].neighbors_id:  
            pos = list()
            position = 0
            #looking for duplicated entries
            for item2 in device_list[i].neighbors_id:
                if item in item2:
                    pos.append(position)
                position += 1
            #Save the position of each entry
            repeated_neig_list.append(pos)

        position = 0
        #For each neighbor of this device
        for repeated in repeated_neig_list:
            
            #Check if this neighbor isnt repeated
            if len(repeated) == 1:
                
                #Save the neighbor into a list
                len_hostname = len(device_list[i].hostname)    
                neighbors_id_single_list.append(device_list[i].hostname[:len_hostname-1])
                
                neighbor_aux = device_list[i].neighbors_id[repeated[0]]
                neighbors_id_single_list.append(neighbor_aux[:len(neighbor_aux)-1])
                
                #Create the list for the interface
                neighbors_interface_list.append(device_list[i].if_to_neighbor_diagram[repeated[0]])
                
                neighbors_id_multi_list.append(neighbors_id_single_list)
                #Clear the list
                neighbors_id_single_list=list()

            #if the neighbors is repeated for this device
            else:
                
                #Save all the interfaces by which this device is connected to the neighbor
                for pos in repeated:
                    if position != pos:
                        interfaces += device_list[i].if_to_neighbor_diagram[pos] + "," 
                
                #Once we are in the last iteration
                if position == max(repeated):
                    
                    #Save all the information about this neighbor
                    len_hostname = len(device_list[i].hostname)
                    neighbors_id_single_list.append(device_list[i].hostname[:len_hostname-1])
                    
                    neighbor_aux = device_list[i].neighbors_id[repeated[0]]
                    neighbors_id_single_list.append(neighbor_aux[:len(neighbor_aux)-1])
                    
                    #Create the list for the interface
                    neighbors_interface_list.append(interfaces[:len(interfaces)-1])
                    neighbors_id_multi_list.append(neighbors_id_single_list)
                    
                    #Clear the list
                    neighbors_id_single_list=list()
            
                    interfaces = ""    
            
            position += 1
        
    #Draw the topology with link's name
    draw_network(neighbors_id_multi_list, neighbors_interface_list)

    

def draw_network(graph, labels=None, graph_layout='shell',
               node_size=1600, node_color='blue', node_alpha=0.3,
               node_text_size=12,
               edge_color='red', edge_alpha=0.2, edge_tickness=1,
               edge_text_pos=0.21,
               text_font='sans-serif'):

    # create networkx graph
    G=nx.Graph()
    
    # add edges
    for edge in graph:
        G.add_edge(edge[0], edge[1])

    graph_pos=nx.shell_layout(G)

    # draw graph
    nx.draw_networkx_nodes(G,graph_pos,node_size=node_size, 
                           alpha=node_alpha, node_color=node_color)

    nx.draw_networkx_edges(G,graph_pos,width=edge_tickness,
                           alpha=edge_alpha,edge_color=edge_color)

    nx.draw_networkx_labels(G, graph_pos,font_size=node_text_size,
                            font_family=text_font)

    #Check the labels of the edges
    if labels is None:
        labels = range(len(graph))
    else:
        edge_labels = {}
        #Create de dict for the links
        for i in range(len(graph)):
            #The keys are the neighbors and the value the interface
            edge_labels[graph[i][1],graph[i][0]] = labels[i]
        nx.draw_networkx_edge_labels(G, graph_pos, edge_labels=edge_labels, label_pos=edge_text_pos)

    # show graph
    plt.show()

def startScan():
    """
        Main function for scan, it makes sure every file is avaiable, if not, exit the program, after that
        call the scan functions and the getEOX function for End Of Support, after call the print topology function and export to csv if checked.
    """
    global passwordPath
    global iprangePath
    global exportPath 
    SNumberList = list()

    exportPath = PathEntry.get() #Get the strings of the Enter() objects of the GUI
    iprangePath = IpEntry.get()
    passwordPath = PassEntry.get()

    if(export.get() and not exportPath):
        print "Set a valid path to export file"
        exit()

    if(not iprangePath or not os.path.isfile(iprangePath)):
        print "Set a valid path to range file"
        exit()

    if(not passwordPath or not os.path.isfile(passwordPath)):
        print "Set a valid path to password file"
        exit()

    device_list = []
    device_list=getValues()

    for i in device_list:
        SNumberList.append(i.serialNumber)

    print ','.join(SNumberList)

    dates = getEOX(','.join(SNumberList))

    #Get the End-of-life of the devices
    for i in device_list:
        if i.serialNumber != "XXXXXXXXXXX" and len(i.serialNumber) == 11:
            dates = getEOX(i.serialNumber)
            i.EOX = dates[0]

        else:
            i.EOX = "Without data"

    """
        Note: The optimum way to get the EOX of all the devices it's using the product ID to get more than one
        EOX date for each call at the API, however, due that in simulation scenarios we can't get an appropiate 
        PID, we can only use the serial number. The API summarizes the EOX results by product ID, so if we use
        the serial number, in case that there are two or more devices with the same product ID, we can't know 
        which EOX belongs to which device, so we only can make it through the Serial Number, and one at the time.
        In real case scenarios, this wouldn't take much time as here.
    """

    #Print the EOX
    print "################### EOX OF DEVICES #####################"
    for i in device_list:
        print i.hostname+": "+i.EOX


    if(export.get()):           #If checked, export to a csv file.
        export_csv(device_list)
    print_topology(device_list)


    

def export_csv(new_device):
    global exportPath 

    with open(exportPath,'wb') as myfile:
        info = ["hw_version", "os_version","serialNumber", "model", "management_ip_address", 
        "password", "hostname", "modules","EOX", "neighbors_id", "if_to_neighbor", "if_name", "if_description", "if_status", "if_line_protocol", "if_to_neighbor_diagram"]

        wr = csv.writer(myfile, quoting = csv.QUOTE_ALL, delimiter =':')
        wr.writerow(info)

        for i in new_device:
            hw_version = i.hw_version
            os_version = i.os_version
            serialNumber = i.serialNumber
            model = i.model
            management_ip_address = i.ip
            password = i.password
            hostname = i.hostname
            modules = i.modules
            EOX = i.EOX
            neighbors_id = i.neighbors_id
            if_to_neighbor = i.if_to_neighbor
            if_name = i.if_name
            if_description = i.if_description
            if_status = i.if_status
            if_line_protocol = i.if_line_protocol
            if_to_neighbor_diagram = i.if_to_neighbor_diagram
            device_info = [hw_version, os_version, serialNumber,model, management_ip_address, password, hostname, modules, EOX,neighbors_id, if_to_neighbor, if_name, if_description, if_status, if_line_protocol,if_to_neighbor_diagram] 
            
            wr.writerow(device_info)

        print "\n################################################################################\n"
        print "Devices' information added to the" + exportPath +" file\n"

def loadScan():
    global exportPath
    exportPath = PathEntry.get()

    if(export.get() and not exportPath):
        print "Set a valid path to export file"
        exit()

    exportPath = PathEntry.get()
    device_list = []

    with open(exportPath,'rb') as csvfile:
        reader = csv.DictReader(csvfile, delimiter =':')
        print ""
        print "_-/\-_ @@@ LOADED SCENARIO @@@ _-/\-_"
        for row in reader:
            new_device = Device()
            new_device.ip = row['management_ip_address']
            new_device.password = row['password']
            new_device.hostname = row['hostname']
            new_device.EOX = row['EOX']
            new_device.serialNumber = row['serialNumber']
            new_device.model = row['model']
            new_device.os_version = row['os_version']
            new_device.hw_version = row['hw_version']
            new_device.modules = eval(row['modules'])
            new_device.if_status = eval(row['if_status'])
            new_device.neighbors_id = eval(row['neighbors_id'])
            new_device.if_to_neighbor = eval(row['if_to_neighbor'])
            new_device.if_name = eval(row['if_name'])
            new_device.if_line_protocol = eval(row['if_line_protocol'])
            new_device.if_description = eval(row['if_description'])
            new_device.if_to_neighbor_diagram = eval(row['if_to_neighbor_diagram'])

            print ""
            print "################################################################################"
            print ""
            print "IP: " + new_device.ip
            print "Hostname: " + new_device.hostname
            print "Password: " + new_device.password
            print "Model: " + new_device.model
            print "OS Version: " + new_device.os_version
            print "HW Version: " + new_device.hw_version
            print "Serial Number: " + new_device.serialNumber
            print "EOX: " + new_device.EOX
            print ""
            print "Modules: "
            print ""
            for i in range (len(new_device.modules)):
                print "    Module " + str(i+1) + ": " + new_device.modules[i][0:len(new_device.modules[i])-1]
            print ""
            
            print "Interfaces status and description:"
            print ""
            for i in range (len(new_device.if_status)):
                print "    Interface: " + new_device.if_name[i] + " Description: " + new_device.if_description[i] + " Status: " + new_device.if_status[i] + " Line Protocol: " + new_device.if_line_protocol[i]
            print ""

            print "Neighbors:"
            print ""
            for i in range(len(new_device.neighbors_id)):
                
                aux_nei = str(new_device.neighbors_id[i])
                
                print "    Neighbor " + str(i+1) + ": " + str(aux_nei[:len(aux_nei)-1]) + " -> via " + new_device.if_to_neighbor[i] + " (" + new_device.if_to_neighbor_diagram[i] + ")"

            device_list.append(new_device);

    print_topology(device_list)

def getEOX(serialNumber):

    """
        This function will get the end of support for Cisco devices using the API for EOX, given a serial number. This function
        can recieve more than one serial number, BUT, each serial number must be sepparated by commas. 
    """

    dates = list()

    url='https://cloudsso.cisco.com/as/token.oauth2' #Url to obtain token for the API via OAuth2.0
    clientid='wzxkkg83w8bgjp6kqg8p2eex'
    clientsecret='GCY7NPUTMSMFpgtQCecpAdFj'

    """
        Now, make a Request object, call it, and load it's content into a json parser, which obtains the bearer acces token.
    """
    r = urllib2.Request(url,"client_id="+clientid+"&grant_type=client_credentials"+"&client_secret="+clientsecret) 
    f = urllib2.urlopen(r)
    data = json.load(f)
    access_token=data['access_token']
    
    """
        By using the bearer token use the EOX API, after that, the function makes sure that the requests/time it's not exceeded.
    """

    bearertoken= "Bearer "+ access_token
    urlapi= 'https://api.cisco.com/supporttools/eox/rest/5/EOXBySerialNumber/1/'+serialNumber+'?responseencoding=json'
    r = urllib2.Request(urlapi,headers={"Authorization":bearertoken})
    f = urllib2.urlopen(r)

    data = json.load(f)
    nresponses= len(data['EOXRecord'])
    
    for i in data['EOXRecord']:
        if 'EOXError' in i:
            dates.append(i['EOXError']['ErrorDescription'])
        else:
            dates.append(i['LastDateOfSupport']['value'])
    time.sleep(60) #Stops the program for 60 seconds, so no overload the API's token
    
    return dates


if __name__=='__main__':

    """
        Here we start to plot the GUI, we create a layout with different frames inside a main box. 
        From here the code start to make calls to the scan options, set the different paths variables, etc. 
        The code was designed with this if __name__ == '__main__' so it can be used as a file not just for 
        a standalone programe, but to provide functions for other programs with the import statement at the beginning.
    """

    exportPath=""               #This will be the global name for the path to the files.
    iprangePath = ""
    passwordPath = ""
    master = tk.Tk()
    master.title("Cisco NetScanner")
    master.geometry("810x400")
    master.resizable(width=False, height=False)

    fmaster = tk.Frame(master, height=500, width=400, bg="white")
    fmaster.pack()

    frame7 = tk.Frame(fmaster, height=100, width = 100,bg="white")
    frame7.pack(side=tk.BOTTOM)

    frame6 = tk.Frame(fmaster, height=100, width = 100,bg="white")
    frame6.pack(side=tk.BOTTOM)

    frame5 = tk.Frame(fmaster, height=100, width = 100,bg="white")
    frame5.pack(side=tk.BOTTOM)

    frame4 = tk.Frame(fmaster, height=100, width = 100,bg="white")
    frame4.pack(side=tk.BOTTOM)

    frame3 = tk.Frame(fmaster, height=100, width = 100,bg="white")
    frame3.pack(side=tk.BOTTOM)

    frame1 = tk.Frame(fmaster, height=100, width = 100,bg="white")
    frame1.pack(side=tk.BOTTOM)



    buttonScan= tk.Button(frame1,text="Scan", command=startScan, bg="white")
    buttonScan.pack(side=tk.LEFT)

    buttonLoad= tk.Button(frame1,text="Load scenario", command=loadScan, bg="white")
    buttonLoad.pack(side=tk.LEFT)

    buttonExit= tk.Button(frame1,text="Exit",command=quit, fg="red", bg="white")
    buttonExit.pack(side=tk.LEFT)

    export=tk.IntVar() #This variable will hold the option for export the results to a CSV.
    checkExport = tk.Checkbutton(frame3,text="Export the file to a CSV?", variable=export, bg="white")
    checkExport.pack(side=tk.BOTTOM)

    pathLab= tk.Label(frame5, text="Path to export file")
    pathLab.pack(side=tk.LEFT)
    PathEntry= tk.Entry(frame5, width=300)
    PathEntry.pack(side=tk.BOTTOM)

    passLab= tk.Label(frame6, text="Path to password file")
    passLab.pack(side=tk.LEFT)
    PassEntry= tk.Entry(frame6, width=300)
    PassEntry.pack(side=tk.BOTTOM)

    IpLab= tk.Label(frame7, text="Path to ip_range file")
    IpLab.pack(side=tk.LEFT)
    IpEntry= tk.Entry(frame7, width=300)
    IpEntry.pack(side=tk.BOTTOM)




    frame2= tk.Frame(fmaster, height=400, width = 300)
    frame2.pack(side=tk.TOP)
    photo = tk.PhotoImage(file="cisco.gif")
    w = tk.Label(frame2, image=photo)
    w.pack()


    master.mainloop() #Start the mainloop for the GUI.