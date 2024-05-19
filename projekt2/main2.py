import subprocess
import os
import logging
import threading
import socket
from datetime import datetime
import argparse

# Set up basic configuration for the logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler("security_script_log.txt")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logger.addHandler(fh)
logger.addHandler(ch)

class SecurityScript:
    def __init__(self):
        self.log = "Security script started\n"
        self.is_running = False
        self.report_thread = None

    def append_to_log(self, string):
        self.log += f"{datetime.now()}: {string}\n"

    def save_ping_log(self, target):
        try:
            with open(f"ping_log_{target}.txt", "a") as file:
                file.write(self.log)
            self.append_to_log(f"Ping log saved to ping_log_{target}.txt")
        except Exception as e:
            self.append_to_log(f"Error saving ping log: {str(e)}")

    def port_scan(self, target):
        explanation = ("Runs a port scan on the target IP, scanning ports from 1 to 1024. "
                       "Useful to find open ports that might be vulnerable.")
        self.append_to_log(f"Starting port scan on {target}")
        try:
            open_ports = []
            for port in range(1, 1025):  # Scan ports 1 to 1024
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            self.append_to_log(f"Open ports on {target}: {open_ports}")
        except Exception as e:
            self.append_to_log(f"Port scan error: {str(e)}")
        print(explanation)

    def ping(self, target):
        explanation = ("Pings the specified target to check if it is reachable. "
                       "Useful to verify network connectivity and if the target is up.")
        self.append_to_log(f"Pinging {target}")
        response = os.system(f"ping -c 1 {target}")
        if response == 0:
            self.append_to_log(f"{target} is up!")
        else:
            self.append_to_log(f"{target} is down!")
        self.save_ping_log(target)
        print(explanation)

    def enable_packet_sniffing(self, interface):
        explanation = ("Enables packet sniffing on the specified network interface. "
                       "Useful for monitoring network traffic and detecting anomalies.")
        self.append_to_log(f"Packet sniffing enabled on {interface}")
        # This would require root privileges and specific packet sniffing tool usage
        # Placeholder for actual packet sniffing code
        print(explanation)

    def run_nmap(self, target):
        explanation = ("Runs Nmap on the specified target IP address. "
                       "Useful for discovering hosts and services on a computer network.")
        self.append_to_log(f"Running Nmap on {target}")
        try:
            result = subprocess.run(["nmap", target], capture_output=True, text=True)
            self.append_to_log(result.stdout)
        except Exception as e:
            self.append_to_log(f"Nmap error: {str(e)}")
        print(explanation)

    def launch_msf_console(self):
        explanation = ("Launches the Metasploit Framework console. "
                       "Useful for conducting penetration testing and security research.")
        self.append_to_log("Launching MSF Console")
        try:
            subprocess.run(["msfconsole"], capture_output=False)
        except Exception as e:
            self.append_to_log(f"MSF Console error: {str(e)}")
        print(explanation)

    def install_security_tools(self):
        explanation = ("Installs recommended security tools like Nmap, Wireshark, and Metasploit. "
                       "Useful for setting up a security testing environment.")
        self.append_to_log("Installing recommended security tools")
        try:
            tools = ["nmap", "wireshark", "metasploit-framework"]
            for tool in tools:
                subprocess.run(["sudo", "apt-get", "install", "-y", tool])
            self.append_to_log("Security tools installed.")
        except Exception as e:
            self.append_to_log(f"Installation error: {str(e)}")
        print(explanation)

    def run_installed_program(self, program):
        explanation = ("Runs any installed security program specified by the user. "
                       "Useful for executing security tools available on the system.")
        self.append_to_log(f"Running installed program: {program}")
        try:
            result = subprocess.run([program], capture_output=True, text=True)
            self.append_to_log(result.stdout)
        except Exception as e:
            self.append_to_log(f"Error running {program}: {str(e)}")
        print(explanation)

    def run_scapy(self):
        explanation = ("Runs the Scapy program for packet manipulation. "
                       "Useful for creating, sending, and sniffing network packets.")
        self.append_to_log("Running SCAPY")
        try:
            from scapy.all import sniff
            packets = sniff(count=10)  # Sniff 10 packets (example)
            self.append_to_log(f"Sniffed packets: {packets.summary()}")
        except Exception as e:
            self.append_to_log(f"Scapy error: {str(e)}")
        print(explanation)

    def shutdown_or_restart(self, action):
        explanation = ("Shuts down or restarts the device based on user choice. "
                       "Useful for remotely managing system power states.")
        self.append_to_log(f"Performing system {action}")
        try:
            if action.lower() == "shutdown":
                os.system("sudo shutdown now")
            elif action.lower() == "restart":
                os.system("sudo reboot")
            self.append_to_log(f"System will {action}.")
        except Exception as e:
            self.append_to_log(f"Error during {action}: {str(e)}")
        print(explanation)

    def display_log(self):
        explanation = ("Displays the current log of activities performed by the security script. "
                       "Useful for reviewing actions and their outcomes.")
        self.append_to_log("Displaying log")
        try:
            with open("security_script_log.txt", "r") as file:
                print(file.read())
        except Exception as e:
            self.append_to_log(f"Error displaying log: {str(e)}")
        print(explanation)

    def report(self):
        if self.is_running:
            logging.info(self.log)
            self.log = ""
            self.report_thread = threading.Timer(5, self.report)
            self.report_thread.start()

    def start(self):
        if not self.is_running:
            self.is_running = True
            logging.info("Security script started.")
            self.report()
        else:
            logging.info("Security script is already running.")

    def stop(self):
        if self.is_running:
            self.is_running = False
            if self.report_thread:
                self.report_thread.cancel()
            logging.info("Security script stopped.")
        else:
            logging.info("Security script is not running.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Security Script for Basic Security Tasks")
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('menu', help="Display the interactive menu")

    port_scan_parser = subparsers.add_parser('port_scan', help="Run a port scan")
    port_scan_parser.add_argument('target', type=str, help="Target IP address")

    ping_parser = subparsers.add_parser('ping', help="Ping a website or PC")
    ping_parser.add_argument('target', type=str, help="Target IP address or URL")

    sniff_parser = subparsers.add_parser('sniff', help="Enable packet sniffing")
    sniff_parser.add_argument('interface', type=str, help="Network interface")

    nmap_parser = subparsers.add_parser('nmap', help="Run Nmap")
    nmap_parser.add_argument('target', type=str, help="Target IP address")

    msf_parser = subparsers.add_parser('msf', help="Launch MSF Console")

    install_parser = subparsers.add_parser('install_tools', help="Install recommended security tools")

    run_prog_parser = subparsers.add_parser('run_program', help="Run any installed security program")
    run_prog_parser.add_argument('program', type=str, help="Program name")

    scapy_parser = subparsers.add_parser('scapy', help="Run SCAPY")

    shutdown_parser = subparsers.add_parser('shutdown', help="Shutdown or restart the device")
    shutdown_parser.add_argument('action', type=str, choices=['shutdown', 'restart'], help="Action: 'shutdown' or 'restart'")

    log_parser = subparsers.add_parser('display_log', help="Display log")

    return parser.parse_args()

def user_menu():
    security_script = SecurityScript()
    menu_options = {
        "1": ("Run a Port Scan", lambda: security_script.port_scan(input("Enter target IP: "))),
        "2": ("Ping a Website or PC", lambda: security_script.ping(input("Enter target IP or URL: "))),
        "3": ("Enable Packet Sniffing", lambda: security_script.enable_packet_sniffing(input("Enter interface: "))),
        "4": ("Run Nmap with a user-specified IP address", lambda: security_script.run_nmap(input("Enter target IP: "))),
        "5": ("Launch MSF Console", security_script.launch_msf_console),
        "6": ("Install all recommended security tools", security_script.install_security_tools),
        "7": ("Run any installed security program", lambda: security_script.run_installed_program(input("Enter program name: "))),
        "8": ("Run the SCAPY program", security_script.run_scapy),
        "9": ("Shutdown or Restart Device", lambda: security_script.shutdown_or_restart(input("Enter 'shutdown' or 'restart': "))),
        "10": ("Display Log", security_script.display_log),
        "11": ("Exit the Program", None)
    }

    while True:
        print("\n--- Security Script Menu ---")
        for key, value in menu_options.items():
            print(f"{key}. {value[0]}")
        choice = input("Select an option: ")

        if choice in menu_options:
            if choice == '11':
                if security_script.is_running:
                    security_script.stop()
                print("Exiting security script...")
                break
            else:
                try:
                    menu_options[choice][1]()
                except Exception as e:
                    print(f"An error occurred: {e}")
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    args = parse_arguments()
    security_script = SecurityScript()

    if args.command == 'menu':
        user_menu()
    elif args.command == 'port_scan':
        security_script.port_scan(args.target)
    elif args.command == 'ping':
        security_script.ping(args.target)
    elif args.command == 'sniff':
        security_script.enable_packet_sniffing(args.interface)
    elif args.command == 'nmap':
        security_script.run_nmap(args.target)
    elif args.command == 'msf':
        security_script.launch_msf_console()
    elif args.command == 'install_tools':
        security_script.install_security_tools()
    elif args.command == 'run_program':
        security_script.run_installed_program(args.program)
    elif args.command == 'scapy':
        security_script.run_scapy()
    elif args.command == 'shutdown':
        security_script.shutdown_or_restart(args.action)
    elif args.command == 'display_log':
        security_script.display_log()
    else:
        print("Invalid command. Use 'menu' for the interactive menu or see --help for other options.")
