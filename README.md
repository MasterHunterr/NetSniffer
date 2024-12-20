# NetSniffer

A simple network packet sniffer written in C++ using the Npcap/WinPcap library. This tool captures and analyzes network packets, displaying their basic details like source and destination IP addresses.

## Features
- Captures live network packets.
- Analyzes IP packets.
- Displays source and destination IP addresses.

## Requirements
- **Npcap** installed on your system.
- A C++ compiler that supports linking with `pcap` libraries (e.g., Visual Studio).

## Installation

### Step 1: Install Npcap
Download and install [Npcap](https://nmap.org/npcap/). Ensure you enable the **WinPcap API-compatible Mode** during installation.

### Step 2: Clone the Repository
```bash
git clone https://github.com/your-username/NetSniffer.git
cd NetSniffer
```

### Step 3: Build the Project
1. Open the project in **Visual Studio**.
2. Add the required libraries (`wpcap.lib` and `Ws2_32.lib`) in the project settings:
   - Go to **Properties > Linker > Input > Additional Dependencies**.
   - Add:
     ```
     wpcap.lib
     Ws2_32.lib
     ```
3. Build the project.

### Step 4: Run the Program
Run the program with administrator privileges to allow packet capture.

## Usage
1. Compile and run the program.
2. The program will automatically select the first available network device.
3. It will capture and display details of 10 network packets.

## Example Output
```
Using device: \Device\NPF_{ABC12345-6789-DEF0-1234-56789ABCDEF0}
Capturing packets...
Packet captured! Length: 66 bytes
Source IP: 192.168.1.2
Destination IP: 192.168.1.1
...
```

## Notes
- This program requires administrative privileges to capture packets.
- It currently supports analyzing Ethernet and IP packets only.
