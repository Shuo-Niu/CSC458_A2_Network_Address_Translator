# CSC458_A2_Network_Address_Translator

### Launch on CDF machines
#### 1. Start VM
```cvm csc458``` (login: "mininet", pswd: \<the password you set>)
#### 2. Run POX controller
```ssh -p 8022 mininet@localhost``` (open a new terminal and ssh to the VM from the same host)

```cd ~/cs144_lab5/```

```./run_pox.sh```
#### 3. Start Mininet emulation
```ssh -p 8022 mininet@localhost``` (open a new terminal and ssh to the VM from the same host)

```cd ~/cs144_lab5/```

```./run_mininet.sh```
#### 4. Build and run the router
```ssh -p 8022 mininet@localhost``` (open a new terminal and ssh to the VM from the same host)

```cd ~/cs144_lab5/router/```

```make```

```./sr```

---
### Pull from Github to update the code on VM
Remove the original project folder on VM and pull the latest version from Github.

```cd ~```

```sudo rm -rf cs144_lab5/```

**Copying my code for your assignment is an academic offence. You have been warned.**

```git clone https://github.com/Shuo-Niu/CSC458_A2_Network_Address_Translator.git cs144_lab5/```

```cd cs144_lab5/```

```git checkout --track remotes/origin/standalone```

```./config.sh```

```cd router/```

```make```

```./sr```

---
### Auto-marker test description
- **ICMP-Traffic-[1-2] [MAX_POINTS = 2]:** Generates an ICMP echo request from client to a random external host. 
Check two packets : 1. an ICMP echo request packet sent from NAT external interface to the external host. 2. an ICMP echo reply packet sent from NAT internal interface to the client.

- **TCP-Traffic-[1-2] [MAX_POINTS = 2]:** Generates an TCP SYN packet from client to a random external host. 
Check two packets: 1. an TCP SYN packet sent from NAT external interface to the external host. 2. an TCP SYN-ACK packet sent from NAT internal interface to the client.

- **ICMPIndep [MAX_POINTS = 1]:** Sends one ICMP echo request from client to a random external host for 10 times. Check : only one external mapping is used.

- **TCPEndpointIndependent [MAX_POINTS = 1]:** Sends one TCP packet to a random external host for 10 times. 
Check : there should be only one port# used for the external address.

- **TCPEndpointIndependentFiltering [MAX_POINTS = 1]:** Client sends a TCP SYN packet to one of the external host(exho1). Get a new mapping (internal port#, internal IP)<=>(external port#, external IP) (Let’s call the external pair Pext). After that, another external host(exho2) sends a TCP SYN packet using Pext as destination (port#, IP) pair. 
Check : a TCP packet should be sent out via NAT internal interface with correct destination port#.

- **TCPSimultaneousOpen [MAX_POINTS = 2]:** The NAT must support the following sequence of TCP packet exchanges.
[SYN ->]
[<- SYN]
[SYN/ACK ->]
[<- SYN/ACK]

- **TCPUnsolicitedSyn [MAX_POINTS = 1]:** Send unsolicited SYN from one of the external hosts to the NAT external interface. It should generate an ICMP port unreachable after 6s ONLY if the destination port to which the packet is sent to is >= 1024.

- **TCPUnsolicitedSyn2 [MAX_POINTS = 1]:** TCPUnsolicitedSyn to restricted external port#(22), It should generate an ICMP port unreachable message too.

- **TCPUnsolicitedSyn3 [MAX_POINTS = 1]:** Send unsolicited SYN from internal host to the NAT internal interface. It should generate an ICMP port unreachable message too.
