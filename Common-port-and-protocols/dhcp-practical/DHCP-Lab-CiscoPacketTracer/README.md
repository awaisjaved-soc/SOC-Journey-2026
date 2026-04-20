
In this lab we will make a basic dhcp server using cisco packet tracer.
below code is the basic configuration process to setup dhcp server that will assgin ip addresses.

```Router>en
Router#config t
Enter configuration commands, one per line.  End with CNTL/Z.
Router(config)#hostname DHCP
DHCP(config)#int f0/0
DHCP(config-if)#ip add 192.168.100.1 255.255.255.0
DHCP(config-if)#no sh

DHCP(config-if)#
%LINK-5-CHANGED: Interface FastEthernet0/0, changed state to up

%LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet0/0, changed state to up

DHCP(config-if)#int f0/1
DHCP(config-if)#ip add 192.168.200.1 255.255.255.0
DHCP(config-if)#no sh

DHCP(config-if)#
%LINK-5-CHANGED: Interface FastEthernet0/1, changed state to up

%LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet0/1, changed state to up

DHCP(config-if)#exit
DHCP(config)#ip dhcp pool 192.168.100.1
DHCP(dhcp-config)#network 192.168.100.0 255.255.255.0
DHCP(dhcp-config)#default-router 192.168.100.1
DHCP(dhcp-config)#exit
DHCP(config)#ip dhcp excluded-address 192.168.100.1
DHCP(config)#ip dhcp excluded-address 192.168.200.1
DHCP(config)#ip dhcp pool 192.168.200.1
DHCP(dhcp-config)#network 192.168.200.0 255.255.255.0
DHCP(dhcp-config)#default-router 192.168.200.1
DHCP(dhcp-config)#exit
DHCP(config)#exit
DHCP#
%SYS-5-CONFIG_I: Configured from console by console

DHCP#wr
Building configuration...
[OK]
DHCP#
DHCP#
