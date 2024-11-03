# Creating and-Implementing Custom Alert Rules in Snort-Intrusion-Detection Systems for Network Protocols

# Objective
The objective of this project is to develop and implement custom alert rules in Snort to effectively detect and prevent suspicious or malicious activities within network traffic. This involves configuring Snort as an Intrusion Detection and Prevention System (IDS/IPS), writing precise rules to monitor specific network protocols (ICMP,FTP,SSH), and analyzing the results to enhance security posture.

### Skills Learned

- Understanding and Writing Snort Rules
- Experience with Network Intrusion Detection/Prevention Systems (IDS/IPS)
- Proficiency in Various Network Protocols Such as ICMP, FTP, and SSH
- Knowledge in Setting Up and Managing Virtual Machines


# Steps

1. Before creating the actual alert for detection, what we need to do is to configure the snort first. This will help us to shorten the command for the snort since it will automatically find the rules directory.

Note: I am using snort 3, so the configuration file will be snort.lua. Unlike on snort 2 which was named snort.conf

        1.1 Go to the snort configuration file which can be found in "/usr/local/etc/snort/snort.lua " and edit the file using text editor

![image](https://github.com/user-attachments/assets/657eaa34-2c80-49cd-8078-df5d3a860ca3)

        1.2 Find the word "IPS", remove the comment for "enable_builtin_rules = true," and add the variable" include = "/usr/local/etc/rules/local.rules"

![image](https://github.com/user-attachments/assets/b5c7a36f-7c5a-4f51-b0ca-2668e712669c)

2. Once the snort has been configured, we can now start creating the rules. In this case, we will create an alert for ICMP protocl which is used mostly for ping. However, if there's a lot of ping command it is possible that the company/organization is experiencing a ICMP ping flood or known as Denial of Service (DOS). Go to the snort local rules file directory which can be found on "/usr/local/etc/rules/local.rules " and use your preferred text editor to edit the file.

        2.1. Based on the image below, this will require an admin privilege and my preferred text editor is nano

![image](https://github.com/user-attachments/assets/273da709-cadf-48e9-9961-d38ac25a3b65)

        2.2. Once the local rules files is open add the following rules "alert icmp any any -> any any ( msg:"ICMP Detected"; sid:1000001; rev:1;)"

        Here is the Rule Breakdown: 
        
        Action: Alert (we want to have an alert regarding to the protocol)
        Protocol: ICMP (protocol we are trying to get)
        Source Ip Address: any (we dont have any specific IP address)
        Source Port: any (we dont any specific Port number)
        Direction: -> (This operator indicates that the rule applies to traffic moving from the source to the destination.)
        Destionation Address: any (we want to use any to detect all of the ICMP alert from external IP)
        Destimnation Port: any (we want to use any to detect all of the ICMP alert from external ports)
        Message: ICMP Detected (the message we preferred when the rule is detected)
        Signature ID: 1000001 (Identification of the rule from other rule)
        Revision: 1 (The number of revision or changes made in the rule)

![image](https://github.com/user-attachments/assets/c6315ef6-c593-41f9-a86d-d522134a475e)


![image](https://github.com/user-attachments/assets/edc4246f-8bd0-48df-b194-ca70b5393a89)

3. Now that we have created our rule, we need to make sure that the syntax we added are working properly

        3.1. Go to the terminal and type "sudo snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules" this command will check if are any errors in the Rules

![image](https://github.com/user-attachments/assets/8d70b044-3275-48a4-ac83-f360cd228931)

        3.2 Based on the result our rule is working properly

![image](https://github.com/user-attachments/assets/cc212703-a67b-46ef-a71e-b3e1d7c46fd8)

4. Now, we are ready to test out the rule. Since we need to generate ICMP traffic through our computer, what we can use is a Virtual Machine to ping the target.

Note: I'm using virtual box, A Kali linux where the Snort can be found and An Ubuntu to generate ICMP traffic. Make sure the the two virtual machine can communicate with each other

        4.1. Before we proceed, we need to know what is our Network Interface in which the snort will be capturing the traffic. In this case, the network interface is "eth0" and the machine IP address which is "192.168.100.164"

![image](https://github.com/user-attachments/assets/8797e3db-2cfc-4c93-9fef-9dcd6d582230)


        4.2. To start test out the rule, type this command in the terminal "sudo snort -c /usr/local/etc/snort/snort.lua -i eth0 -A alert_fast -q"
        Command Breakdown:
        "sudo": Snort requires admin privilege
        "snort -c /usr/local/etc/snort/snort.lua": this the snort configuration file directory
        "-i eth0": this is our network interface
        "-A alert_fast": This option sets the alert mode to alert_fast, which means that alerts will be printed to the console as they occur in a summarized format.

![image](https://github.com/user-attachments/assets/9e459a17-c344-47a5-80a8-2cf5ceec0f0e)

This is what it looks like when you press the enter, and it means the snort is working

![image](https://github.com/user-attachments/assets/28c57719-4664-4926-a6a5-5eaa97890def)

        4.3 On the other Virtual Machine which is an Ubuntu, ping the target machine which has the IP: 192.168.100.164

![image](https://github.com/user-attachments/assets/3cfb505c-8935-4612-9c9f-32dc3d0687b0)

        4.4 As you can see on the Kali Linux Machine where the snort is running that the rule was able to detect the ICMP traffic from the Ubuntu Machine.

![image](https://github.com/user-attachments/assets/c9e366e5-f4b7-4eb4-875e-6f9a3e6a82b8)

5. To do the same with the SSH protocol, we are just going to edit the rules based on the protocol and the port number for SSH

        5.1. Once the local rules files is open add the following rules "alert tcp any any -> any 22 ( msg:"SSH Traffic Detected"; sid:1000001; rev:1;)" and test the rule just like we did on 3.1

   Here is the Rule Breakdown:
   
        Action: Alert (we want to have an alert regarding to the protocol)
        Protocol: TCP (there is no direct SSH protocl since it is under the TCP protocol)
        Source Ip Address: any (we dont have any specific IP address)
        Source Port: 22 (we use port 22 since it is the given port for SSH)
        Direction: -> (This operator indicates that the rule applies to traffic moving from the source to the destination.)
        Destionation Address: any (we want to use any to detect all of the ICMP alert from external IP)
        Destimnation Port: any (we want to use any to detect all of the ICMP alert from external ports)
        Message: ICMP Detected (the message we preferred when the rule is detected)
        Signature ID: 1000001 (Identification of the rule from other rule)
        Revision: 1 (The number of revision or changes made in the rule)

![image](https://github.com/user-attachments/assets/8e6aaebc-b390-4335-9b1f-d5b5d518e6c7)

        
6. To test out again the rule, type this command in the terminal "sudo snort -c /usr/local/etc/snort/snort.lua -i eth0 -A alert_fast -q".

           6.1. It will show the same photo from 4.2

   ![image](https://github.com/user-attachments/assets/fac5643c-8f87-49cc-906d-bf165f320371)

7. Same as the previous process, use the Ubuntu Virtual Machine to connect the Target Machine via SSH. The command for connecting the to SSH via linux command "ssh jlwafu@192.169.100.164"

   ![image](https://github.com/user-attachments/assets/dae3aa3f-9864-4c36-9a31-fe280e452886)

           7.1 Based on the results, our rule is able to detect a SSH connection

   ![image](https://github.com/user-attachments/assets/3d248fdd-4b74-45cd-bc19-9ec619ebdf00)

8. Lastly, To do the same with the FTP protocol, we are just going to edit the rules based on the protocol and the port number for FTP

           8.1 Once the local rules files is open add the following rules "alert ftp any any -> 192.168.100.154 21 (msg: "FTP Traffic Detected"; sid:100003; rev:1;)" and test the rule just like we did on 5.1
  
  Here is the Rule Breakdown: 
  
        Action: Alert (we want to have an alert regarding to the protocol)
        Protocol: ftp (protocol we are trying to get)
        Source Ip Address: any (we dont have any specific IP address)
        Source Port: any (we dont any specific Port number)
        Direction: -> (This operator indicates that the rule applies to traffic moving from the source to the destination.)
        Destionation Address: 192.168.100.154 (we want to use any FTP traffic from our Ubuntu Machine)
        Destimnation Port: any (we will use port 21 for FTP)
        Message: ICMP Detected (the message we preferred when the rule is detected)
        Signature ID: 1000001 (Identification of the rule from other rule)
        Revision: 1 (The number of revision or changes made in the rule)

   ![image](https://github.com/user-attachments/assets/08e04ef0-4507-4e3d-908f-8b58ea9e83e3)

9. To test out again the rule, type this command in the terminal "sudo snort -c /usr/local/etc/snort/snort.lua -i eth0 -A alert_fast -q".

           9.1 It will show the same photo from 4.2

   ![image](https://github.com/user-attachments/assets/fac5643c-8f87-49cc-906d-bf165f320371)

10. Same as the previous process, use the Ubuntu Virtual Machine to connect the Target Machine via SSH. The command for connecting the to SSH via linux command "ssh jlwafu@192.169.100.164"

