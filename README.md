# Creating-and-Implementing-Custom-Alert-Rules-in-Snort-Intrusion-Detection-and-Prevention-Systems

# Objective
The objective of this project is to develop and implement custom alert rules in Snort to effectively detect and prevent suspicious or malicious activities within network traffic. This involves configuring Snort as an Intrusion Detection and Prevention System (IDS/IPS), writing precise rules to monitor specific network protocols (ICMP,FTP,SSH), and analyzing the results to enhance security posture.

### Skills Learned

- Understanding and Writing Snort Rules
- Experience with Network Intrusion Detection/Prevention Systems (IDS/IPS)
- Proficiency in Various Network Protocols Such as ICMP, FTP, and SSH
- 

# Steps

1. Before creating the actual alert for detection, what we need to do is to configure the snort first. Go to the snort configuration file which can be found in "/usr/local/etc/snort/snort.lua
" and edit the file using text editor (as shown in the photo below 1.1). Find the word "IPS", remove the comment for "enable_builtin_rules = true," and add the variable" include = "/usr/local/etc/rules/local.rules" (as shown in photo below 1.2), This will help us not to provide a long format of command for the snort since it will automatically find the rules directory.

Note: I am using snort 3, so the configuration file will be snort.lua. Unlike on snort 2 which was named snort.conf

    1.1

![image](https://github.com/user-attachments/assets/657eaa34-2c80-49cd-8078-df5d3a860ca3)

    1.2

![image](https://github.com/user-attachments/assets/b5c7a36f-7c5a-4f51-b0ca-2668e712669c)

