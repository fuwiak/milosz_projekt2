Sure! Here is an example of how to create a `README.md` file that provides instructions on how to run each option in the script using command-line arguments.

```markdown
# Security Script

This security script allows non-cyber security professionals to run basic security programs. It includes functionalities such as port scanning, pinging, packet sniffing, running Nmap, and more.

## Prerequisites

- Python 3.x
- Required Python modules: `argparse`, `logging`, `datetime`, `subprocess`, `os`, `threading`, `socket`
- Scapy (for packet manipulation): `pip install scapy`
- Metasploit Framework: Follow installation instructions from the [Metasploit website](https://www.metasploit.com/)

## Usage

You can run this script in two ways:
1. **Interactive Menu**: Launches a menu-based interface.
2. **Command-Line Arguments**: Run specific functions directly from the command line.

### Running the Interactive Menu

To start the interactive menu, use:
```bash
python main2.py menu
```

### Running Specific Functions with Command-Line Arguments

#### 1. Run a Port Scan
Scans ports from 1 to 1024 on the target IP address.
```bash
python main2.py port_scan <target_ip>
```
**Example:**
```bash
python main2.py port_scan 192.168.1.1
```

#### 2. Ping a Website or PC
Pings the specified target to check if it is reachable.
```bash
python main2.py ping <target_ip_or_url>
```
**Example:**
```bash
python main2.py ping wp.pl
```

#### 3. Enable Packet Sniffing
Enables packet sniffing on the specified network interface.
```bash
python main2.py sniff <interface>
```
**Example:**
```bash
python main2.py sniff eth0
```

#### 4. Run Nmap
Runs Nmap on the specified target IP address.
```bash
python main2.py nmap <target_ip>
```
**Example:**
```bash
python main2.py nmap 192.168.1.1
```

#### 5. Launch MSF Console
Launches the Metasploit Framework console.
```bash
python main2.py msf
```

#### 6. Install Recommended Security Tools
Installs recommended security tools like Nmap, Wireshark, and Metasploit.
```bash
python main2.py install_tools
```

#### 7. Run Any Installed Security Program
Runs any installed security program specified by the user.
```bash
python main2.py run_program <program_name>
```
**Example:**
```bash
python main2.py run_program nmap
```

#### 8. Run SCAPY
Runs the Scapy program for packet manipulation.
```bash
python main2.py scapy
```

#### 9. Shutdown or Restart Device
Shuts down or restarts the device based on user choice.
```bash
python main2.py shutdown <action>
```
**Example:**
```bash
python main2.py shutdown shutdown
```
or
```bash
python main2.py shutdown restart
```

#### 10. Display Log
Displays the current log of activities performed by the security script.
```bash
python main2.py display_log
```

