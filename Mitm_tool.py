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

# Configuration and rest of the imports remain the same...

class MITMTool:
    # ... (previous methods remain the same until interactive_menu)
    
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
        
    def show_scan_menu(self):
        """Display network scanning menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        print("\n" + "="*50)
        print(" NETWORK SCANNING MENU".center(50))
        print("="*50)
        print("\n1. Quick ARP Scan (arp-scan)")
        print("2. Comprehensive Nmap Scan")
        print("3. Ping Sweep")
        print("4. Return to Main Menu")
        
    def show_mitm_menu(self):
        """Display MITM attack menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        print("\n" + "="*50)
        print(" MITM ATTACK MENU".center(50))
        print("="*50)
        print("\n1. ARP Spoofing")
        print("2. DNS Spoofing (via bettercap)")
        print("3. SSL Stripping")
        print("4. Return to Main Menu")
        
    def show_capture_menu(self):
        """Display packet capture menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        print("\n" + "="*50)
        print(" PACKET CAPTURE MENU".center(50))
        print("="*50)
        print("\n1. Start TCPDump Capture")
        print("2. View Active Captures")
        print("3. Stop All Captures")
        print("4. Return to Main Menu")
        
    def show_credential_menu(self):
        """Display credential harvesting menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        print("\n" + "="*50)
        print(" CREDENTIAL HARVESTING MENU".center(50))
        print("="*50)
        print("\n1. Start Responder (NTLM/LLMNR)")
        print("2. Start Bettercap (HTTP/SMB)")
        print("3. View Captured Credentials")
        print("4. Return to Main Menu")
        
    def show_config_menu(self):
        """Display configuration menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        print("\n" + "="*50)
        print(" CONFIGURATION MENU".center(50))
        print("="*50)
        print("\n1. Configure Allowed Networks")
        print("2. Toggle Remote Upload")
        print("3. View Current Configuration")
        print("4. Return to Main Menu")

    def interactive_menu(self):
        """Enhanced interactive menu with submenus"""
        while True:
            self.show_main_menu()
            choice = input("\nSelect an option (1-7): ").strip()
            
            try:
                if choice == "1":  # Network Scanning
                    self.handle_scan_menu()
                elif choice == "2":  # MITM Attacks
                    self.handle_mitm_menu()
                elif choice == "3":  # Packet Capture
                    self.handle_capture_menu()
                elif choice == "4":  # Credential Harvesting
                    self.handle_credential_menu()
                elif choice == "5":  # Configuration
                    self.handle_config_menu()
                elif choice == "6":  # Stop All
                    self.stop_all_attacks()
                    input("\nPress Enter to continue...")
                elif choice == "7":  # Exit
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

    def handle_scan_menu(self):
        """Handle network scanning menu"""
        while True:
            self.show_scan_menu()
            choice = input("\nSelect an option (1-4): ").strip()
            
            if choice == "1":
                self.network_scan()
                input("\nPress Enter to continue...")
            elif choice == "2":
                self.run_comprehensive_nmap()
                input("\nPress Enter to continue...")
            elif choice == "3":
                self.run_ping_sweep()
                input("\nPress Enter to continue...")
            elif choice == "4":
                break
            else:
                print("Invalid choice")
                time.sleep(1)

    def handle_mitm_menu(self):
        """Handle MITM attack menu"""
        while True:
            self.show_mitm_menu()
            choice = input("\nSelect an option (1-4): ").strip()
            
            if choice == "1":
                target = input("Enter target IP: ").strip()
                gateway = input("Enter gateway IP: ").strip()
                self.arp_spoof(target, gateway)
                input("\nPress Enter to continue...")
            elif choice == "2":
                self.start_dns_spoofing()
                input("\nPress Enter to continue...")
            elif choice == "3":
                self.start_ssl_stripping()
                input("\nPress Enter to continue...")
            elif choice == "4":
                break
            else:
                print("Invalid choice")
                time.sleep(1)

    # ... (similar handler methods for other menus)

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