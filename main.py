#!/usr/bin/env python3
"""
NmapGhost - Professional Network Reconnaissance
Full-Featured Nmap Automation for CTFs, Certifications & Daily Use
Author: Cenidev
Version: 1.0
"""

import argparse
import sys
import os
from rich.console import Console


def main():
    """Función principal - Ejecuta modo interactivo por defecto"""
    parser = argparse.ArgumentParser(
        description='NmapGhost - Professional Network Reconnaissance '
    )
    
    parser.add_argument('--check-deps', action='store_true',
                       help='Verify system dependencies')
    parser.add_argument('--version', action='store_true',
                       help='Show version information')
    
    args = parser.parse_args()
    
    console = Console()
    
    if args.version:
        console.print("[bold bright_blue]NmapGhost v1.0[/bold bright_blue]")
        console.print("[green]Professional Network Reconnaissance [/green]")
        return
    
    if args.check_deps:
        try:
            import nmap
            import rich
            console.print("[bright_green]✓ All dependencies operational[/bright_green]")
            
            if os.system("which nmap > /dev/null 2>&1") != 0:
                console.print("[bright_red]✗ Nmap not installed on system[/bright_red]")
                return
            console.print("[bright_green]✓ System ready for Ultimate operations[/bright_green]")
        except ImportError as e:
            console.print(f"[bright_red]✗ Missing dependency: {e}[/bright_red]")
        return
    
    # Modo interactivo por defecto (SIN ARGUMENTOS)
    try:
        from interactive_menu import NmapGhostUltimate
        ultimate_app = NmapGhostUltimate()
        ultimate_app.main_menu()
    except ImportError as e:
        console.print(f"[bright_red]Import Error: {e}[/bright_red]")
        console.print("[yellow]Make sure interactive_menu.py is in the same directory[/yellow]")


if __name__ == "__main__":
    main()
