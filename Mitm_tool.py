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
            with open(CFIG_FILE) as f:
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

    # ... [Rest of the methods remain the same as in the original script]

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
