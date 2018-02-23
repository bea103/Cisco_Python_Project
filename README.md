# Cisco_Python_Project

The aim of this project is providing a solution to the following issue:

1.	Knowing all available devices in the network. For each device, is needed to know:
  -	Hardware version.
  -	OS version running on the device.
  -	Management ip address.
  -	Password.
  -	Modules which are installed on the device - and status of each module.
2.	Topology
3.	Seeing the interface description and interface status for each interface on each device. 
4.	Designing a tool which will be able to report end of life/end of support for the available hardware/OS in the network. 

For this purpose, we have designed a graphic interface. The interface will look like this:
# ![Logo](media/graphic_interface.png)

First of all, is needed to attach two files (the path has to be the absolute one, name of the file included):
  1. The first file is <i>password.txt</i> (the name cannot be changed). This file must contain all passwords of all          devices in the network. In order to be read properly, there must be just one password per line. A good example of a <i>password.txt</i> could be:
  <br>password1 <br>
  password2 <br>
  password3
  
  2. The second file needed to run our application is the <i>iprange.txt</i> file (like the other one, the name cannot be changed). This file must contain the iprange of the network plus the mask (all IPs can be in the same line but separated by commas). The structure of this file must be like the following (ip/mask, ip2/mask2, etc...):
  <br>192.168.2.0/24, 192.168.3.0/24
  
After providing all the information above, we can run the application by clicking on the scan button.
 
The application will start its scan of the network printing via console all the information related with the devices found. 
An example of this output can be the following picture:

# ![Console_output](media/console_output.png)

In addition, the application will display a topology map through a GUI. This map will show all devices and all the connections with the other ones. It will also be possible to see the names of al used interfaces. This map will be similar to the following one:

# ![Topology_Map](media/topology_map.png)

