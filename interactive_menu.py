#!/usr/bin/env python3
"""
NmapGhost - Professional Reconnaissance Framework
Complete Nmap Integration for Penetration Testing & CTF
Author: Cenidev
Version: 1.0

"""

import os
import sys
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich import box
import nmap
import subprocess
from datetime import datetime
import random
import platform 

COLORS = {
    'primary': 'bright_red',
    'success': 'bright_green', 
    'warning': 'bright_yellow',
    'error': 'bright_red',
    'info': 'bright_white',
    'accent': 'bright_magenta',
    'secondary': 'cyan'
}

class NmapGhostUltimate:
    def __init__(self):
        # Console multiplataforma para Windows
        import platform
        self.is_windows = platform.system() == 'Windows'
        if self.is_windows:
            self.console = Console(force_terminal=True, legacy_windows=False, width=120)
        else:
            self.console = Console()
        
        self.nm = nmap.PortScanner()
        self.config = {
            'target': '',
            'scan_type': '',
            'ports': '',
            'scan_method': 'sS',
            'timing_template': '4',
            'service_detection': True,
            'version_intensity': 7,
            'os_detection': False,
            'aggressive_scan': False,
            'traceroute': False,
            'nse_scripts': [],
            'ping_scan': True,
            'fragment_packets': False,
            'decoy_addresses': [],
            'source_port': '',
            'dns_resolution': True,
            'verbosity': 0,
            'custom_flags': [],
            'exclude_targets': '',
            'min_rate': None,
            'max_rate': None
        }
        
        # Templates profesionales
        self.templates = {
            'ejpt': {
                'name': 'ePJT Reconnaissance',
                'description': 'ePJT exam methodology',
                'config': {
                    'ports': '--top-ports 1000',
                    'service_detection': True,
                    'nse_scripts': ['default', 'safe'],
                    'timing_template': '4'
                }
            },
            'oscp': {
                'name': 'OSCP Enumeration', 
                'description': 'OSCP exam focused scan',
                'config': {
                    'ports': '-p-',
                    'service_detection': True,
                    'os_detection': True,
                    'version_intensity': 9,
                    'nse_scripts': ['default', 'vuln'],
                    'timing_template': '4'
                }
            },
            'ctf_quick': {
                'name': 'CTF Quick Scan',
                'description': 'Fast CTF enumeration',
                'config': {
                    'ports': '--top-ports 1000',
                    'service_detection': True,
                    'timing_template': '5',
                    'nse_scripts': ['default']
                }
            },
            'ctf_deep': {
                'name': 'CTF Deep Scan',
                'description': 'Complete CTF analysis',
                'config': {
                    'ports': '-p-',
                    'service_detection': True,
                    'os_detection': True,
                    'version_intensity': 9,
                    'nse_scripts': ['default', 'vuln', 'safe'],
                    'timing_template': '4',
                    'traceroute': True
                }
            },
            'stealth': {
                'name': 'Stealth Scan',
                'description': 'Low-profile reconnaissance', 
                'config': {
                    'ports': '--top-ports 100',
                    'timing_template': '2',
                    'fragment_packets': True,
                    'nse_scripts': ['safe']
                }
            },
            'vuln': {
                'name': 'Vulnerability Assessment',
                'description': 'Security vulnerability scan',
                'config': {
                    'ports': '--top-ports 1000',
                    'service_detection': True,
                    'version_intensity': 9,
                    'nse_scripts': ['vuln'],
                    'timing_template': '4'
                }
            },
            'web': {
                'name': 'Web Application Scan',
                'description': 'Web app security assessment',
                'config': {
                    'ports': '-p 80,443,8080,8443,8000,3000,5000,9000',
                    'service_detection': True,
                    'nse_scripts': ['http-*', 'ssl-*'],
                    'version_intensity': 9
                }
            },
            'discovery': {
                'name': 'Network Discovery',
                'description': 'Host discovery and mapping',
                'config': {
                    'ports': '--top-ports 100', 
                    'ping_scan': True,
                    'timing_template': '3'
                }
            }
        }

        # NSE Scripts categorizados
        self.nse_categories = {
            'auth': ['auth-owners', 'ftp-anon', 'http-auth', 'mysql-empty-password'],
            'brute': ['ftp-brute', 'http-brute', 'ssh-brute', 'mysql-brute', 'smtp-brute'],
            'default': ['http-title', 'ssl-cert', 'ssh-hostkey', 'banner'],
            'discovery': ['broadcast-dhcp-discover', 'dns-brute', 'snmp-sysdescr'],
            'exploit': ['http-shellshock', 'smb-vuln-ms17-010', 'ssl-poodle'],
            'intrusive': ['http-sql-injection', 'smtp-open-relay'],
            'safe': ['banner', 'http-title', 'smb-os-discovery', 'ssl-cert'],
            'version': ['banner', 'ftp-syst', 'http-server-header'],
            'vuln': ['ssl-heartbleed', 'smb-vuln-ms08-067', 'http-vuln-cve2017-5638']
        }

    def clear_screen(self):
        """Función de limpieza multiplataforma"""
        try:
            if self.is_windows:
                os.system('cls')
            else:
                os.system('clear')
        except:
            print('\n' * 50)



    def show_banner(self):
        
        # Tu ASCII Art enmarcado
        banner_art = """
    ┌────────────────────────────────────────────────────────────────┐
    │    _   ____  ______    ____     ________  ______  ___________  │
    │   / | / /  |/  /   |  / __ \\   / ____/ / / / __ \\/ ___/_  __/  │
    │  /  |/ / /|_/ / /| | / /_/ /  / / __/ /_/ / / / /__ \\  / /     │
    │ / /|  / /  / / ___ |/ ____/  / /_/ / __  / /_/ /___/ // /      │
    │/_/ |_/_/  /_/_/  |_/_/       \\____/_/ /_/\\____//____//_/       │
    │                                                                │
    │           PROFESSIONAL RECONNAISSANCE FRAMEWORK                │
    └────────────────────────────────────────────────────────────────┘
    
        """
        
        # Colores
        primary_color = COLORS['primary']
        secondary_color = COLORS['secondary']
        warning_color = COLORS['warning']
        info_color = COLORS['info']
        accent_color = COLORS['accent']
        
        # Banner con marco
        self.console.print(f"[bold {accent_color}]{banner_art}[/bold {accent_color}]")
        
        # Resto de funcionalidad
        self.console.print(f"\n[bold {primary_color}]NmapGhost - Professional Framework[/bold {primary_color}]")
        self.console.print(f"[{secondary_color}]Complete Nmap Integration for Penetration Testing[/{secondary_color}]")
        self.console.print("[dim]Author: Cenidev [/dim]")
        
        if self.config['target']:
            self.console.print(f"\n[{warning_color}]Target: {self.config['target']}[/{warning_color}]")
            if self.config['scan_type']:
                self.console.print(f"[{info_color}]Profile: {self.config['scan_type']}[/{info_color}]")
        
        self.console.print("[dim]" + "─" * 70 + "[/dim]")

    def show_menu(self):
        """Menú principal"""
        options = [
            ("1", "Target Configuration", "Configure target specification"),
            ("2", "Scan Templates", "Professional scan profiles"),  
            ("3", "Port Scanning", "Port configuration and scan types"),
            ("4", "Service Detection", "Version and service enumeration"),
            ("5", "OS Detection", "Operating system identification"),
            ("6", "NSE Scripts", "Nmap Scripting Engine"),
            ("7", "Timing & Performance", "Speed and performance tuning"),
            ("8", "Stealth & Evasion", "IDS/IPS evasion techniques"),
            ("9", "Host Discovery", "Ping and discovery options"),
            ("10", "Output & Logging", "Output formats and logging"),
            ("11", "Execute Scan", "Launch configured scan"),
            ("12", "Raw Nmap", "Execute custom nmap commands"),
            ("13", "View Results", "Display scan results"),
            ("0", "Exit", "Exit NmapGhost")
        ]
        
        primary_color = COLORS['primary']
        self.console.print(f"\n[bold {primary_color}]Available Options:[/bold {primary_color}]")
        
        for num, name, desc in options:
            if num == '11':
                color = COLORS['error']
            elif num in ['1', '2']:
                color = COLORS['accent'] 
            elif num == '12':
                color = COLORS['warning']
            else:
                color = COLORS['info']
            
            self.console.print(f"[{color}]{num.rjust(2)}[/{color}] - {name} ({desc})")

    def main_menu(self):
        """Loop principal"""
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_menu()
            
            try:
                primary_color = COLORS['primary']
                choice = Prompt.ask(
                    f"\n[bold {primary_color}]Select option[/bold {primary_color}]",
                    choices=["0","1","2","3","4","5","6","7","8","9","10","11","12","13"],
                    default="1"
                )
                
                if choice == "0":
                    success_color = COLORS['success']
                    self.console.print(f"\n[{success_color}]Thanks for using NmapGhost Professional![/{success_color}]")
                    break
                elif choice == "1": self.configure_target()
                elif choice == "2": self.select_template()
                elif choice == "3": self.configure_port_scanning()
                elif choice == "4": self.configure_service_detection()
                elif choice == "5": self.configure_os_detection()
                elif choice == "6": self.configure_nse()
                elif choice == "7": self.configure_timing()
                elif choice == "8": self.configure_stealth()
                elif choice == "9": self.configure_host_discovery()
                elif choice == "10": self.configure_output()
                elif choice == "11": self.execute_scan()
                elif choice == "12": self.raw_nmap()
                elif choice == "13": self.view_results()
                    
            except KeyboardInterrupt:
                warning_color = COLORS['warning']
                if Confirm.ask(f"\n[{warning_color}]Exit NmapGhost?[/{warning_color}]"):
                    break

    def configure_target(self):
        """Configuración completa de targets"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Target Configuration[/bold {primary_color}]\n")
        
        if self.config['target']:
            info_color = COLORS['info']
            self.console.print(f"[{info_color}]Current: {self.config['target']}[/{info_color}]\n")
        
        options = [
            ("1", "Single IP", "192.168.1.100"),
            ("2", "CIDR Network", "192.168.1.0/24"),
            ("3", "IP Range", "192.168.1.1-50"),
            ("4", "Multiple IPs", "192.168.1.1,192.168.1.100"),
            ("5", "Hostname/FQDN", "target.domain.com"),
            ("6", "Target File", "/path/to/targets.txt")
        ]
        
        accent_color = COLORS['accent']
        for num, name, example in options:
            self.console.print(f"[{accent_color}]{num}[/{accent_color}] - {name} (e.g., {example})")
        
        choice = Prompt.ask(f"\n[{accent_color}]Select target type[/{accent_color}]", choices=["1","2","3","4","5","6"], default="1")
        
        success_color = COLORS['success']
        target = Prompt.ask(f"[{success_color}]Enter target specification[/{success_color}]")
        
        if choice == "6" and not os.path.exists(target):
            error_color = COLORS['error']
            self.console.print(f"[{error_color}]File not found: {target}[/{error_color}]")
            Prompt.ask("Press ENTER to continue...")
            return
        
        self.config['target'] = target
        
        # Exclusiones
        info_color = COLORS['info']
        if Confirm.ask(f"[{info_color}]Configure target exclusions?[/{info_color}]", default=False):
            exclude = Prompt.ask("Enter targets to exclude (comma-separated)", default="")
            self.config['exclude_targets'] = exclude
        
        self.console.print(f"\n[{success_color}]✓ Target configured: {target}[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def select_template(self):
        """Templates profesionales"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Professional Scan Templates[/bold {primary_color}]\n")
        
        template_list = [
            ("1", "ejpt", "Certification"),
            ("2", "oscp", "Certification"), 
            ("3", "ctf_quick", "CTF"),
            ("4", "ctf_deep", "CTF"),
            ("5", "stealth", "Specialized"),
            ("6", "vuln", "Security"),
            ("7", "web", "Web Apps"),
            ("8", "discovery", "Discovery")
        ]
        
        accent_color = COLORS['accent']
        for num, key, category in template_list:
            template = self.templates[key]
            self.console.print(f"[{accent_color}]{num}[/{accent_color}] - {template['name']} ({category})")
            self.console.print(f"    {template['description']}")
        
        choice = Prompt.ask(f"\n[{accent_color}]Select template[/{accent_color}]", choices=[str(i) for i in range(1, 9)], default="1")
        
        selected_key = template_list[int(choice)-1][1]
        template = self.templates[selected_key]
        
        # Aplicar configuración del template
        self.config['scan_type'] = template['name']
        if 'config' in template:
            for key, value in template['config'].items():
                self.config[key] = value
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ Template applied: {template['name']}[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def configure_port_scanning(self):
        """Configuración completa de escaneo de puertos"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Port Scanning Configuration[/bold {primary_color}]\n")
        
        # Port ranges
        info_color = COLORS['info']
        self.console.print(f"[{info_color}]Port Specification:[/{info_color}]")
        port_options = [
            ("1", "Top 100 ports", "--top-ports 100"),
            ("2", "Top 1000 ports", "--top-ports 1000"),
            ("3", "Top 5000 ports", "--top-ports 5000"),
            ("4", "All ports (1-65535)", "-p-"),
            ("5", "Common ports", "-p 21,22,23,25,53,80,110,135,139,143,443,993,995,3389,5900"),
            ("6", "Web ports", "-p 80,443,8080,8443,8000,3000,5000,9000"),
            ("7", "Database ports", "-p 1433,1521,3306,5432,6379,27017"),
            ("8", "Custom range", "-p 1-1000"),
            ("9", "Specific ports", "-p 22,80,443,3389")
        ]
        
        accent_color = COLORS['accent']
        for num, desc, cmd in port_options:
            self.console.print(f"[{accent_color}]{num}[/{accent_color}] - {desc}")
        
        port_choice = Prompt.ask(f"\n[{accent_color}]Select port range[/{accent_color}]", choices=[str(i) for i in range(1, 10)], default="2")
        
        if port_choice == "8":
            custom_range = Prompt.ask("Enter custom port range (e.g., 1-1000)")
            self.config['ports'] = f"-p {custom_range}"
        elif port_choice == "9":
            custom_ports = Prompt.ask("Enter specific ports (e.g., 22,80,443)")
            self.config['ports'] = f"-p {custom_ports}"
        else:
            self.config['ports'] = port_options[int(port_choice)-1][2]
        
        # Scan methods
        self.console.print(f"\n[{info_color}]Scan Methods:[/{info_color}]")
        scan_methods = [
            ("1", "TCP SYN Scan", "sS", "Fast, stealthy (requires root)"),
            ("2", "TCP Connect Scan", "sT", "Complete TCP handshake"),
            ("3", "UDP Scan", "sU", "UDP port scanning"),
            ("4", "TCP ACK Scan", "sA", "Firewall rule detection"),
            ("5", "TCP FIN Scan", "sF", "Stealth scan technique"),
            ("6", "TCP NULL Scan", "sN", "Stealth scan technique"),
            ("7", "TCP Xmas Scan", "sX", "Stealth scan technique"),
            ("8", "TCP Maimon Scan", "sM", "Stealth scan technique"),
            ("9", "TCP Window Scan", "sW", "Advanced scan technique"),
            ("10", "SCTP INIT Scan", "sY", "SCTP protocol scan"),
            ("11", "SCTP COOKIE-ECHO", "sZ", "SCTP protocol scan"),
            ("12", "IP Protocol Scan", "sO", "IP protocol enumeration")
        ]
        
        for num, name, flag, desc in scan_methods:
            current = " ← CURRENT" if self.config.get('scan_method') == flag else ""
            self.console.print(f"[{accent_color}]{num.rjust(2)}[/{accent_color}] - {name} (-s{flag}) - {desc}{current}")
        
        method_choice = Prompt.ask(f"\n[{accent_color}]Select scan method[/{accent_color}]", choices=[str(i) for i in range(1, 13)], default="1")
        
        self.config['scan_method'] = scan_methods[int(method_choice)-1][2]
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ Port scanning configured[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def configure_service_detection(self):
        """Configuración de detección de servicios"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Service Detection Configuration[/bold {primary_color}]\n")
        
        # Service detection
        service_detection = Confirm.ask("Enable service version detection (-sV)?", default=self.config.get('service_detection', True))
        self.config['service_detection'] = service_detection
        
        if service_detection:
            info_color = COLORS['info']
            self.console.print(f"\n[{info_color}]Version Detection Intensity:[/{info_color}]")
            self.console.print("0 - Light mode (fastest)")
            self.console.print("1-4 - Light to moderate")
            self.console.print("5-6 - Moderate intensity")
            self.console.print("7 - Default intensity")
            self.console.print("8-9 - Aggressive (slower)")
            
            intensity = IntPrompt.ask("Version detection intensity (0-9)", default=self.config.get('version_intensity', 7))
            self.config['version_intensity'] = min(9, max(0, intensity))
        
        # RPC info
        rpc_info = Confirm.ask("\nEnable RPC info detection (-sR)?", default=False)
        if rpc_info:
            if 'custom_flags' not in self.config:
                self.config['custom_flags'] = []
            self.config['custom_flags'].append("-sR")
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ Service detection configured[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def configure_os_detection(self):
        """Configuración de detección de SO"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]OS Detection Configuration[/bold {primary_color}]\n")
        
        # Basic OS detection
        os_detection = Confirm.ask("Enable OS detection (-O)?", default=self.config.get('os_detection', False))
        self.config['os_detection'] = os_detection
        
        if os_detection:
            # Advanced OS detection options
            info_color = COLORS['info']
            self.console.print(f"\n[{info_color}]Advanced OS Detection Options:[/{info_color}]")
            
            osscan_limit = Confirm.ask("Limit OS detection to promising targets (--osscan-limit)?", default=False)
            if osscan_limit:
                if 'custom_flags' not in self.config:
                    self.config['custom_flags'] = []
                self.config['custom_flags'].append("--osscan-limit")
            
            osscan_guess = Confirm.ask("Guess OS more aggressively (--osscan-guess)?", default=False)
            if osscan_guess:
                if 'custom_flags' not in self.config:
                    self.config['custom_flags'] = []
                self.config['custom_flags'].append("--osscan-guess")
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ OS detection configured[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def configure_nse(self):
        """Configuración completa NSE"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]NSE Scripts Configuration[/bold {primary_color}]\n")
        
        if self.config.get('nse_scripts'):
            info_color = COLORS['info']
            active = ', '.join(self.config['nse_scripts'])
            self.console.print(f"[{info_color}]Active: {active}[/{info_color}]\n")
        
        # Show categories
        accent_color = COLORS['accent']
        for i, (category, scripts) in enumerate(self.nse_categories.items(), 1):
            active = "✓" if category in self.config.get('nse_scripts', []) else " "
            risk_colors = {'auth': 'yellow', 'brute': 'red', 'exploit': 'bright_red', 'intrusive': 'red'}
            color = risk_colors.get(category, 'green')
            
            self.console.print(f"[{accent_color}]{i:2d}[/{accent_color}] {active} {category.upper()} ({len(scripts)} scripts) - [{color}]RISK[/{color}]")
        
        action = Prompt.ask(f"[{accent_color}]Action[/{accent_color}]", choices=["add", "remove", "clear", "custom", "done"], default="done")
        
        success_color = COLORS['success']
        
        if action == "add":
            categories = Prompt.ask("Enter categories to add (numbers, comma-separated)")
            category_list = list(self.nse_categories.keys())
            for choice in categories.split(','):
                try:
                    idx = int(choice.strip()) - 1
                    if 0 <= idx < len(category_list):
                        cat = category_list[idx]
                        if 'nse_scripts' not in self.config:
                            self.config['nse_scripts'] = []
                        if cat not in self.config['nse_scripts']:
                            self.config['nse_scripts'].append(cat)
                            self.console.print(f"[{success_color}]✓ Added {cat}[/{success_color}]")
                except ValueError:
                    continue
                    
        elif action == "remove":
            to_remove = Prompt.ask("Enter category to remove")
            if 'nse_scripts' in self.config and to_remove in self.config['nse_scripts']:
                self.config['nse_scripts'].remove(to_remove)
                self.console.print(f"[{success_color}]✓ Removed {to_remove}[/{success_color}]")
                
        elif action == "clear":
            self.config['nse_scripts'] = []
            self.console.print(f"[{success_color}]✓ Cleared all scripts[/{success_color}]")
            
        elif action == "custom":
            custom_scripts = Prompt.ask("Enter custom NSE scripts (comma-separated)")
            if 'nse_scripts' not in self.config:
                self.config['nse_scripts'] = []
            self.config['nse_scripts'].extend([s.strip() for s in custom_scripts.split(',')])
            self.console.print(f"[{success_color}]✓ Added custom scripts[/{success_color}]")
        
        if action != "done":
            Prompt.ask("\nPress ENTER to continue...")
            self.configure_nse()
        else:
            Prompt.ask("Press ENTER to continue...")

    def configure_timing(self):
        """Configuración de timing y performance"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Timing & Performance Configuration[/bold {primary_color}]\n")
        
        # Timing templates
        timing_options = [
            ("T0", "Paranoid", "300s+ delays", "IDS evasion"),
            ("T1", "Sneaky", "15s delays", "Slow scanning"),
            ("T2", "Polite", "0.4s delays", "Low bandwidth"), 
            ("T3", "Normal", "Default timing", "Normal scanning"),
            ("T4", "Aggressive", "Fast scanning", "Common choice"),
            ("T5", "Insane", "Very fast", "May crash services")
        ]
        
        info_color = COLORS['info']
        self.console.print(f"[{info_color}]Timing Templates:[/{info_color}]")
        accent_color = COLORS['accent']
        for timing, name, delay, desc in timing_options:
            current = " ← CURRENT" if self.config.get('timing_template') == timing[1:] else ""
            self.console.print(f"[{accent_color}]{timing}[/{accent_color}] - {name}: {desc}{current}")
        
        current_timing = f"T{self.config.get('timing_template', '4')}"
        timing_choice = Prompt.ask(f"\n[{accent_color}]Select timing[/{accent_color}]", choices=["T0","T1","T2","T3","T4","T5"], default=current_timing)
        self.config['timing_template'] = timing_choice[1:]
        
        # Advanced timing options
        if Confirm.ask(f"\n[{info_color}]Configure advanced timing options?[/{info_color}]", default=False):
            
            # Parallelism
            parallelism = IntPrompt.ask("Max parallel hosts (0=default)", default=0)
            if parallelism > 0:
                if 'custom_flags' not in self.config:
                    self.config['custom_flags'] = []
                self.config['custom_flags'].append(f"--max-parallelism {parallelism}")
            
            # Scan delay
            scan_delay = IntPrompt.ask("Scan delay in ms (0=default)", default=0)
            if scan_delay > 0:
                if 'custom_flags' not in self.config:
                    self.config['custom_flags'] = []
                self.config['custom_flags'].append(f"--scan-delay {scan_delay}ms")
            
            # Min/Max rate
            min_rate = IntPrompt.ask("Minimum packet rate (0=default)", default=0)
            if min_rate > 0:
                self.config['min_rate'] = min_rate
            
            max_rate = IntPrompt.ask("Maximum packet rate (0=default)", default=0) 
            if max_rate > 0:
                self.config['max_rate'] = max_rate
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ Timing configured: {timing_choice}[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def configure_stealth(self):
        """Configuración de técnicas de evasión"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Stealth & Evasion Configuration[/bold {primary_color}]\n")
        
        techniques = [
            ("1", "Fragment packets (-f)", "Split packets into 8-byte fragments"),
            ("2", "Decoy scanning (-D)", "Use decoy IP addresses"),
            ("3", "Idle zombie scan (-sI)", "Use zombie host for scanning"),
            ("4", "Source port spoofing (--source-port)", "Spoof source port"),
            ("5", "Source IP spoofing (-S)", "Spoof source IP address"),
            ("6", "Random data length (--data-length)", "Append random data"),
            ("7", "IP options (--ip-options)", "Set IP options"),
            ("8", "TTL manipulation (--ttl)", "Set time to live"),
            ("9", "Spoof MAC address (--spoof-mac)", "Spoof MAC address"),
            ("10", "Bad checksum (--badsum)", "Use bad checksums")
        ]
        
        info_color = COLORS['info']
        self.console.print(f"[{info_color}]Available Evasion Techniques:[/{info_color}]")
        accent_color = COLORS['accent']
        for num, name, desc in techniques:
            self.console.print(f"[{accent_color}]{num.rjust(2)}[/{accent_color}] - {name}")
            self.console.print(f"    {desc}")
        
        choices = Prompt.ask(f"\n[{accent_color}]Select techniques (comma-separated, or 'none')[/{accent_color}]", default="none")
        
        if choices != "none":
            if 'custom_flags' not in self.config:
                self.config['custom_flags'] = []
            
            for choice in choices.split(','):
                choice = choice.strip()
                
                if choice == "1":
                    self.config['fragment_packets'] = True
                elif choice == "2":
                    num_decoys = IntPrompt.ask("Number of decoy IPs", default=3)
                    decoys = []
                    for _ in range(num_decoys):
                        decoy = f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                        decoys.append(decoy)
                    self.config['decoy_addresses'] = decoys
                elif choice == "3":
                    zombie_host = Prompt.ask("Enter zombie host IP")
                    self.config['custom_flags'].append(f"-sI {zombie_host}")
                elif choice == "4":
                    source_port = IntPrompt.ask("Source port (53=DNS, 80=HTTP)", default=53)
                    self.config['source_port'] = str(source_port)
                elif choice == "5":
                    source_ip = Prompt.ask("Source IP to spoof")
                    self.config['custom_flags'].append(f"-S {source_ip}")
                elif choice == "6":
                    data_length = IntPrompt.ask("Random data length", default=32)
                    self.config['custom_flags'].append(f"--data-length {data_length}")
                elif choice == "7":
                    ip_options = Prompt.ask("IP options (e.g., R for record route)")
                    self.config['custom_flags'].append(f"--ip-options {ip_options}")
                elif choice == "8":
                    ttl = IntPrompt.ask("TTL value", default=64)
                    self.config['custom_flags'].append(f"--ttl {ttl}")
                elif choice == "9":
                    mac_type = Prompt.ask("MAC type (0=random, vendor name, or MAC)", default="0")
                    self.config['custom_flags'].append(f"--spoof-mac {mac_type}")
                elif choice == "10":
                    self.config['custom_flags'].append("--badsum")
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ Stealth techniques configured[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def configure_host_discovery(self):
        """Configuración de descubrimiento de hosts"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Host Discovery Configuration[/bold {primary_color}]\n")
        
        # Ping options
        ping_options = [
            ("1", "ICMP Echo Ping (-PE)", "Standard ping"),
            ("2", "ICMP Timestamp (-PP)", "ICMP timestamp request"),
            ("3", "ICMP Netmask (-PM)", "ICMP netmask request"),
            ("4", "TCP SYN Ping (-PS)", "TCP SYN to common ports"),
            ("5", "TCP ACK Ping (-PA)", "TCP ACK ping"),
            ("6", "UDP Ping (-PU)", "UDP ping to common ports"),
            ("7", "SCTP INIT Ping (-PY)", "SCTP INIT ping"),
            ("8", "ARP Ping (-PR)", "ARP discovery (local network)"),
            ("9", "Never do DNS resolution (-n)", "Skip reverse DNS"),
            ("10", "Skip host discovery (-Pn)", "Treat all hosts as online")
        ]
        
        info_color = COLORS['info']
        self.console.print(f"[{info_color}]Host Discovery Options:[/{info_color}]")
        accent_color = COLORS['accent']
        for num, name, desc in ping_options:
            self.console.print(f"[{accent_color}]{num.rjust(2)}[/{accent_color}] - {name} - {desc}")
        
        choices = Prompt.ask(f"\n[{accent_color}]Select discovery methods (comma-separated)[/{accent_color}]", default="1")
        
        if 'custom_flags' not in self.config:
            self.config['custom_flags'] = []
        
        for choice in choices.split(','):
            choice = choice.strip()
            if choice == "1":
                self.config['custom_flags'].append("-PE")
            elif choice == "2":
                self.config['custom_flags'].append("-PP")
            elif choice == "3":
                self.config['custom_flags'].append("-PM")
            elif choice == "4":
                ports = Prompt.ask("TCP SYN ping ports (default: 80)", default="80")
                self.config['custom_flags'].append(f"-PS{ports}")
            elif choice == "5":
                ports = Prompt.ask("TCP ACK ping ports (default: 80)", default="80")
                self.config['custom_flags'].append(f"-PA{ports}")
            elif choice == "6":
                ports = Prompt.ask("UDP ping ports (default: 40125)", default="40125")
                self.config['custom_flags'].append(f"-PU{ports}")
            elif choice == "7":
                ports = Prompt.ask("SCTP ping ports (default: 80)", default="80")
                self.config['custom_flags'].append(f"-PY{ports}")
            elif choice == "8":
                self.config['custom_flags'].append("-PR")
            elif choice == "9":
                self.config['dns_resolution'] = False
            elif choice == "10":
                self.config['ping_scan'] = False
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ Host discovery configured[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def configure_output(self):
        """Configuración de salida y logging"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Output & Logging Configuration[/bold {primary_color}]\n")
        
        # Verbosity
        info_color = COLORS['info']
        self.console.print(f"[{info_color}]Verbosity Levels:[/{info_color}]")
        self.console.print("0 - No extra output")
        self.console.print("1 - Show open ports (-v)")
        self.console.print("2 - Show closed/filtered ports (-vv)")
        self.console.print("3 - Maximum verbosity (-vvv)")
        
        verbosity = IntPrompt.ask("\nVerbosity level (0-3)", default=self.config.get('verbosity', 0))
        self.config['verbosity'] = min(3, max(0, verbosity))
        
        # Output formats
        self.console.print(f"\n[{info_color}]Output Formats:[/{info_color}]")
        if Confirm.ask("Save normal output (-oN)?", default=True):
            if 'custom_flags' not in self.config:
                self.config['custom_flags'] = []
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.config['custom_flags'].append(f"-oN scan_{timestamp}.nmap")
        
        if Confirm.ask("Save XML output (-oX)?", default=False):
            if 'custom_flags' not in self.config:
                self.config['custom_flags'] = []
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.config['custom_flags'].append(f"-oX scan_{timestamp}.xml")
        
        if Confirm.ask("Save grepable output (-oG)?", default=False):
            if 'custom_flags' not in self.config:
                self.config['custom_flags'] = []
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.config['custom_flags'].append(f"-oG scan_{timestamp}.gnmap")
        
        # Debug options
        if Confirm.ask("\nEnable packet tracing (--packet-trace)?", default=False):
            if 'custom_flags' not in self.config:
                self.config['custom_flags'] = []
            self.config['custom_flags'].append("--packet-trace")
        
        success_color = COLORS['success']
        self.console.print(f"\n[{success_color}]✓ Output options configured[/{success_color}]")
        Prompt.ask("Press ENTER to continue...")

    def execute_scan(self):
        """Ejecutor principal"""
        if not self.config['target']:
            error_color = COLORS['error']
            self.console.print(f"[{error_color}]No target configured. Use option 1 first.[/{error_color}]")
            Prompt.ask("Press ENTER to continue...")
            return
        
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Execute Scan[/bold {primary_color}]\n")
        
        # Construir comando
        nmap_cmd = self.build_nmap_command()
        
        info_color = COLORS['info']
        self.console.print(f"[{info_color}]Target: {self.config['target']}[/{info_color}]")
        self.console.print(f"[{info_color}]Profile: {self.config.get('scan_type', 'Custom')}[/{info_color}]")
        self.console.print(f"[{info_color}]Command: nmap {nmap_cmd}[/{info_color}]")
        
        # Warnings
        self.show_warnings()
        
        accent_color = COLORS['accent']
        if not Confirm.ask(f"\n[{accent_color}]Execute scan?[/{accent_color}]", default=True):
            return
        
        try:
            self.console.print(f"\n[{primary_color}]Starting scan...[/{primary_color}]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeRemainingColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task("Scanning...", total=None)
                start_time = datetime.now()
                result = self.nm.scan(self.config['target'], arguments=nmap_cmd)
                end_time = datetime.now()
            
            duration = end_time - start_time
            hosts_found = len(self.nm.all_hosts())
            
            success_color = COLORS['success']
            self.console.print(f"\n[{success_color}]Scan completed in {duration}[/{success_color}]")
            self.console.print(f"[{info_color}]Hosts discovered: {hosts_found}[/{info_color}]")
            
            if hosts_found > 0:
                if Confirm.ask(f"\n[{info_color}]Display results?[/{info_color}]", default=True):
                    self.display_results()
            else:
                warning_color = COLORS['warning']
                self.console.print(f"[{warning_color}]No hosts found or all filtered[/{warning_color}]")
            
        except KeyboardInterrupt:
            warning_color = COLORS['warning']
            self.console.print(f"\n[{warning_color}]Scan interrupted[/{warning_color}]")
        except Exception as e:
            error_color = COLORS['error']
            self.console.print(f"\n[{error_color}]Scan failed: {str(e)}[/{error_color}]")
        
        Prompt.ask("\nPress ENTER to continue...")

    def show_warnings(self):
        """Mostrar advertencias"""
        warnings = []
        if 'exploit' in self.config.get('nse_scripts', []):
            warnings.append("EXPLOIT scripts may damage systems")
        if 'brute' in self.config.get('nse_scripts', []):
            warnings.append("BRUTE FORCE scripts may lock accounts")
        if self.config.get('timing_template') == '5':
            warnings.append("INSANE timing may crash services")
        
        if warnings:
            warning_color = COLORS['warning']
            self.console.print(f"\n[{warning_color}]WARNINGS:[/{warning_color}]")
            for warning in warnings:
                self.console.print(f"  ⚠ {warning}")

    def build_nmap_command(self):
        """Construir comando nmap"""
        cmd_parts = []
        
        # Scan method
        if self.config.get('scan_method'):
            scan_method = self.config['scan_method']
            if scan_method.startswith('s'):  # Ya incluye la 's' inicial
                cmd_parts.append(f"-{scan_method}")
            else:
                cmd_parts.append(f"-s{scan_method}")

        
        # Ports
        if self.config.get('ports'):
            cmd_parts.append(self.config['ports'])
        else:
            cmd_parts.append("--top-ports 1000")
        
        # Timing
        timing = self.config.get('timing_template', '4')
        cmd_parts.append(f"-T{timing}")
        
        # Service detection
        if self.config.get('service_detection'):
            intensity = self.config.get('version_intensity', 7)
            cmd_parts.append(f"-sV --version-intensity {intensity}")
        
        # OS detection
        if self.config.get('os_detection'):
            cmd_parts.append("-O")
        
        # Aggressive scan
        if self.config.get('aggressive_scan'):
            cmd_parts.append("-A")
        
        # Traceroute
        if self.config.get('traceroute'):
            cmd_parts.append("--traceroute")
        
        # NSE Scripts
        if self.config.get('nse_scripts'):
            all_scripts = []
            for category in self.config['nse_scripts']:
                if category in self.nse_categories:
                    all_scripts.extend(self.nse_categories[category])
                else:
                    all_scripts.append(category)  # Custom script
            
            if all_scripts:
                unique_scripts = list(set(all_scripts))
                cmd_parts.append(f"--script {','.join(unique_scripts)}")
        
        # Stealth options
        if self.config.get('fragment_packets'):
            cmd_parts.append("-f")
        
        if self.config.get('decoy_addresses'):
            decoys = ','.join(self.config['decoy_addresses'])
            cmd_parts.append(f"-D {decoys}")
        
        if self.config.get('source_port'):
            cmd_parts.append(f"--source-port {self.config['source_port']}")
        
        # Host discovery
        if not self.config.get('ping_scan', True):
            cmd_parts.append("-Pn")
        
        # DNS resolution
        if not self.config.get('dns_resolution', True):
            cmd_parts.append("-n")
        
        # Performance
        if self.config.get('min_rate'):
            cmd_parts.append(f"--min-rate {self.config['min_rate']}")
        
        if self.config.get('max_rate'):
            cmd_parts.append(f"--max-rate {self.config['max_rate']}")
        
        # Verbosity
        if self.config.get('verbosity', 0) > 0:
            cmd_parts.append(f"-{'v' * self.config['verbosity']}")
        
        # Exclude targets
        if self.config.get('exclude_targets'):
            cmd_parts.append(f"--exclude {self.config['exclude_targets']}")
        
        # Custom flags
        if self.config.get('custom_flags'):
            cmd_parts.extend(self.config['custom_flags'])
        
        return ' '.join(cmd_parts)

    def display_results(self):
        """Mostrar resultados"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Scan Results[/bold {primary_color}]\n")
        
        for host in self.nm.all_hosts():
            host_info = self.nm[host]
            hostname = host_info.hostname() or "Unknown"
            state = host_info.state()
            
            state_color = COLORS['success'] if state == 'up' else COLORS['error']
            self.console.print(f"[{state_color}]Host: {host}[/{state_color}] ({hostname}) - {state.upper()}")
            
            if host_info.all_protocols():
                accent_color = COLORS['accent']
                table = Table(show_header=True, header_style=f"bold {accent_color}")
                table.add_column("Port", width=12)
                table.add_column("State", width=10)
                table.add_column("Service", width=15)
                table.add_column("Version", width=40)
                
                for protocol in host_info.all_protocols():
                    for port in host_info[protocol].keys():
                        port_info = host_info[protocol][port]
                        port_state = port_info['state']
                        service = port_info.get('name', 'unknown')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        
                        port_color = COLORS['success'] if port_state == 'open' else COLORS['error']
                        version_info = f"{product} {version}".strip() or "Not detected"
                        
                        table.add_row(
                            f"{port}/{protocol}",
                            f"[{port_color}]{port_state}[/{port_color}]",
                            service,
                            version_info
                        )
                
                self.console.print(table)
            
            self.console.print()
        
        info_color = COLORS['info']
        if Confirm.ask(f"[{info_color}]Save results to file?[/{info_color}]", default=True):
            self.save_results()
        
        Prompt.ask("Press ENTER to continue...")

    def save_results(self):
        """Guardar resultados"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nmapghost_results_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("="*60 + "\n")
                f.write("NMAPGHOST PROFESSIONAL - SCAN RESULTS\n")
                f.write("="*60 + "\n\n")
                f.write(f"Scan Date: {datetime.now()}\n")
                f.write(f"Target: {self.config['target']}\n")
                f.write(f"Command: nmap {self.build_nmap_command()}\n\n")
                
                for host in self.nm.all_hosts():
                    host_info = self.nm[host]
                    f.write(f"Host: {host} ({host_info.hostname() or 'Unknown'})\n")
                    f.write(f"State: {host_info.state().upper()}\n\n")
                    
                    if host_info.all_protocols():
                        f.write("Open Ports:\n")
                        for protocol in host_info.all_protocols():
                            for port in host_info[protocol].keys():
                                port_info = host_info[protocol][port]
                                if port_info['state'] == 'open':
                                    service = port_info.get('name', 'unknown')
                                    product = port_info.get('product', '')
                                    version = port_info.get('version', '')
                                    f.write(f"  {port}/{protocol} - {service}")
                                    if product or version:
                                        f.write(f" ({product} {version})")
                                    f.write("\n")
                    f.write("\n" + "-"*40 + "\n\n")
            
            success_color = COLORS['success']
            self.console.print(f"[{success_color}]✓ Results saved to {filename}[/{success_color}]")
            
        except Exception as e:
            error_color = COLORS['error']
            self.console.print(f"[{error_color}]Error saving: {str(e)}[/{error_color}]")

    def raw_nmap(self):
        """Ejecutor raw nmap"""
        self.clear_screen()
        primary_color = COLORS['primary']
        self.console.print(f"[bold {primary_color}]Raw Nmap Execution[/bold {primary_color}]\n")
        
        info_color = COLORS['info']
        self.console.print(f"[{info_color}]Examples:[/{info_color}]")
        examples = [
            "-sS -sV --script vuln 192.168.1.1",
            "-sU --top-ports 100 target.com", 
            "-A -T4 target.com",
            "-sn 192.168.1.0/24",
            "--script smb-enum-shares 192.168.1.0/24"
        ]
        
        for example in examples:
            self.console.print(f"  nmap {example}")
        
        accent_color = COLORS['accent']
        command = Prompt.ask(f"\n[{accent_color}]Enter nmap command (without 'nmap')[/{accent_color}]")
        
        if not command.strip():
            error_color = COLORS['error']
            self.console.print(f"[{error_color}]Empty command[/{error_color}]")
            Prompt.ask("Press ENTER to continue...")
            return
        
        full_command = f"nmap {command}"
        self.console.print(f"\n[{info_color}]Executing: {full_command}[/{info_color}]")
        
        if not Confirm.ask(f"[{accent_color}]Continue?[/{accent_color}]", default=True):
            return
        
        try:
            self.console.print(f"\n[{primary_color}]Output:[/{primary_color}]")
            process = subprocess.Popen(full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.console.print(output.strip())
            
            exit_code = process.poll()
            success_color = COLORS['success']
            self.console.print(f"\n[{success_color}]Command completed (exit code: {exit_code})[/{success_color}]")
            
        except Exception as e:
            error_color = COLORS['error']
            self.console.print(f"\n[{error_color}]Error: {str(e)}[/{error_color}]")
        
        Prompt.ask("\nPress ENTER to continue...")

    def view_results(self):
        """Ver resultados"""
        if hasattr(self, 'nm') and self.nm.all_hosts():
            self.display_results()
        else:
            warning_color = COLORS['warning']
            self.console.print(f"[{warning_color}]No scan results available[/{warning_color}]")
            Prompt.ask("Press ENTER to continue...")

if __name__ == "__main__":
    ghost = NmapGhostUltimate()
    ghost.main_menu()
