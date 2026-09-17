# Poison Ivy Remote Access Trojan Analysis & Threat Detection Logic

### Threat Profile Overview

Poison Ivy is a Remote Access Trojan (RAT) that was identified in 2005 and has been prevalent in cybercrime for years after. It has been used to target government organizations, chemical manufacturers, human rights groups, and defence contractors by a large variety of hacking groups and operations, including at least three separate advanced persistent threat (APT) campaigns. It was designed for the purpose of remotely monitoring victims while also exfiltrating user credentials and files. It is often spread through malicious Word or PDF attachments in spearphishing emails. In 2013, FireEye disseminated a detailed report on Poison Ivy and provided its typical attack sequence:

- The attacker sets up a custom Poison Ivy (PIVY) server, incorporating details on how the RAT will install itself on the target computer, enabled features, and the encryption password, among others.
- The attacker sends the PIVY server installation file to the target's computer. The target opens the infected email and executes the file, or visits a compromised website.
- The server installation file executes on the target computer and downloads additional code through an encrypted communication channel to avoid antivirus detection.
- Once the PIVY server is running on the target machine, the attacker uses a Windows GUI client to control the target computer

### Purpose

This project aims to do some self analysis of Poison Ivy through reverse engineering for learning purposes, so that based on our findings we can create our own sigma and yara rules. 

## Reverse Engineering (Ghidra) 
