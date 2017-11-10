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
