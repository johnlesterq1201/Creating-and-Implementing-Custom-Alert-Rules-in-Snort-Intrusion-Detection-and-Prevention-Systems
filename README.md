![image](https://github.com/user-attachments/assets/fd151a86-1e28-44c7-8b33-fbc5eab0d81d)# Creating-and-Implementing-Custom-Alert-Rules-in-Snort-Intrusion-Detection-and-Prevention-Systems

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
        "-A alert_fast":  
