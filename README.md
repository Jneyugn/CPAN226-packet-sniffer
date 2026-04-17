# Raw Packet Sniffer & Protocol Analyzer

## CPAN226 Network Programming Project - Project #12

### Description
A raw packet sniffer in C that captures live network traffic and displays:
- **MAC addresses** (Ethernet layer)
- **TTL values** (IP layer)  
- **Port numbers** (TCP/UDP layer)

### How to Run:
#### Requirements
- Windows with WSL (Windows Subsystem for Linux) OR native Linux
- GCC compiler
- Root/sudo privileges

#### Step 1: Install WSL (Windows users only)
Open PowerShell as Administrator and run:
wsl --install

Restart your computer, then launch Ubuntu from the Start menu.

#### Step 2: Compile the Program
In the WSL/Linux terminal, navigate to the file and run:
gcc sniffer.c -o sniffer

#### Step 3: Run the Sniffer
sudo ./sniffer

#### Step 4: Generate Test Traffic
Open a second WSL terminal and run:

ping google.com
or
curl http://example.com

#### Step 5: Stop the Program
Press `Ctrl + C`

### Sample Output
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ETHERNET]
Source MAC: 00:15:5d:5f:44:95
Destination MAC: 00:15:5d:a2:79:db
[IP]
TTL (Time To Live): 64
[TCP]
Source Port: 34636
Destination Port: 80
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Author
Jenny Nguyen - CPAN226
