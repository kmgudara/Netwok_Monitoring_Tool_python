import tkinter as tk
from tkinter import ttk, scrolledtext
import psutil
import socket
import threading
import requests
import ipaddress
import csv
import scapy.all as scapy
import os

def load_mac_db(filepath):
    """Load the MAC address database from the CSV file."""
    mac_db = {}
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) >= 2:
                    mac_prefix = row[0].strip().replace(":", "").upper()
                    manufacturer = row[1].strip()
                    mac_db[mac_prefix] = manufacturer
    except Exception as e:
        print(f"Error loading MAC database: {e}")
    return mac_db

def get_network_interfaces():
    """Get list of network interfaces with their IP addresses and netmasks."""
    interfaces = psutil.net_if_addrs()
    interface_list = []
    
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4 addresses
                interface_list.append((interface, addr.address, addr.netmask))
    
    return interface_list

def get_ip_and_subnet(selected_interface):
    """Get the IP address and subnet of a selected interface."""
    addrs = psutil.net_if_addrs()[selected_interface]
    ip_address = None
    netmask = None

    for addr in addrs:
        if addr.family == socket.AF_INET:
            ip_address = addr.address
            netmask = addr.netmask
            break

    return ip_address, netmask

def netmask_to_cidr(netmask):
    """Convert netmask to CIDR notation."""
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def get_wifi_interface():
    """Find the WiFi interface from available network interfaces."""
    interfaces = psutil.net_if_addrs()
    wifi_interfaces = []
    
    # Common WiFi interface names
    wifi_keywords = ['wifi', 'wireless', 'wlan', 'wi-fi']
    
    for iface in interfaces:
        iface_lower = iface.lower()
        if any(keyword in iface_lower for keyword in wifi_keywords):
            wifi_interfaces.append(iface)
    
    # If no WiFi interface found, return the first active interface
    if not wifi_interfaces:
        for iface in interfaces:
            if iface in psutil.net_if_stats():
                stats = psutil.net_if_stats()[iface]
                if stats.isup:
                    return iface
    
    # Return the first WiFi interface found
    return wifi_interfaces[0] if wifi_interfaces else None

def arp_scan(subnet, mac_db, results_var, treeview, status_label, scan_button, progress_frame, progress_bar, progress_label, progress_var):
    """Perform ARP scan on the given subnet."""
    try:
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request

        # Update progress to 10% - starting scan
        progress_var.set(10)
        progress_label.config(text="Starting network scan...")

        # Send packet and get response
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        # Update progress to 50% - scan complete, processing results
        progress_var.set(50)
        progress_label.config(text="Processing scan results...")

        # Clear existing items
        for item in treeview.get_children():
            treeview.delete(item)

        # Process results
        total_devices = len(answered_list)
        for i, element in enumerate(answered_list):
            ip = element[1].psrc
            mac = element[1].hwsrc
            mac_prefix = mac.replace(":", "").upper()[:6]
            manufacturer = mac_db.get(mac_prefix, "Unknown")

            # Insert into treeview
            treeview.insert("", "end", values=(ip, mac, manufacturer))
            
            # Update progress from 50% to 100% based on devices processed
            progress = 50 + (i + 1) / total_devices * 50 if total_devices > 0 else 100
            progress_var.set(progress)
            progress_label.config(text=f"Processing device {i+1} of {total_devices}")

        status_label.config(text=f"Scan completed. Found {len(answered_list)} devices.")
    except Exception as e:
        status_label.config(text=f"Error during scan: {str(e)}")
    finally:
        # Set progress to 100% and hide after a short delay
        progress_var.set(100)
        progress_label.config(text="Scan completed!")
        
        # Hide progress bar after a short delay
        def hide_progress():
            progress_frame.after(1000, progress_frame.pack_forget)
        
        progress_frame.after(1000, hide_progress)
        scan_button.config(state="normal")

def create_page04(parent_frame):
    """Create the ARP Scanner page."""
    # Create main container
    main_container = ttk.Frame(parent_frame)
    main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Title
    title_label = ttk.Label(
        main_container,
        text="ARP Scanner",
        font=("Arial", 18, "bold")
    )
    title_label.pack(pady=(0, 20))

    # Create interface selection frame
    interface_frame = ttk.LabelFrame(main_container, text="Network Interface", padding=10)
    interface_frame.pack(fill=tk.X, pady=(0, 10))

    # Get network interfaces
    interfaces = get_network_interfaces()
    interface_names = [iface[0] for iface in interfaces]

    # Create interface label
    interface_label = ttk.Label(interface_frame, text="Select Interface:")
    interface_label.pack(side=tk.LEFT, padx=5)

    # Create interface combobox
    interface_var = tk.StringVar()
    interface_combo = ttk.Combobox(interface_frame, textvariable=interface_var)
    interface_combo['values'] = interface_names
    interface_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    
    # Set default to WiFi interface if available
    default_interface = get_wifi_interface()
    if default_interface and default_interface in interface_names:
        interface_combo.set(default_interface)
    elif interface_names:
        interface_combo.set(interface_names[0])

    # Create results frame
    results_frame = ttk.LabelFrame(main_container, text="Scan Results", padding=10)
    results_frame.pack(fill=tk.BOTH, expand=True, pady=5)

    # Create treeview for results
    columns = ("IP Address", "MAC Address", "Manufacturer")
    device_table = ttk.Treeview(results_frame, columns=columns, show="headings", height=10)

    # Configure columns
    device_table.column("IP Address", width=150, anchor="center")
    device_table.column("MAC Address", width=150, anchor="center")
    device_table.column("Manufacturer", width=200, anchor="center")

    # Set headings
    device_table.heading("IP Address", text="IP Address")
    device_table.heading("MAC Address", text="MAC Address")
    device_table.heading("Manufacturer", text="Manufacturer")

    # Add scrollbar
    scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=device_table.yview)
    device_table.configure(yscrollcommand=scrollbar.set)

    # Pack treeview and scrollbar
    device_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Create progress frame (initially hidden)
    progress_frame = ttk.Frame(main_container)
    progress_frame.pack(fill=tk.X, pady=5)
    progress_frame.pack_forget()  # Hide initially
    
    # Create progress bar
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(
        progress_frame, 
        variable=progress_var,
        maximum=100,
        mode='determinate'  # Use determinate mode for scanning
    )
    progress_bar.pack(fill=tk.X, padx=5, pady=5)
    
    # Create progress label
    progress_label = ttk.Label(progress_frame, text="Scanning network...")
    progress_label.pack(pady=(0, 5))

    # Create status label
    status_label = ttk.Label(main_container, text="Ready to scan")
    status_label.pack(fill=tk.X, pady=5)

    # Create scan button
    scan_button = ttk.Button(
        main_container,
        text="Start Scan",
        command=lambda: start_scan(
            interface_combo, 
            interfaces, 
            None, 
            device_table, 
            status_label, 
            scan_button,
            progress_frame,
            progress_bar,
            progress_label,
            progress_var
        )
    )
    scan_button.pack(pady=5)

    return main_container

def start_scan(interface_combo, interfaces, results_var, device_table, status_label, scan_button, progress_frame, progress_bar, progress_label, progress_var):
    """Start the ARP scan process."""
    try:
        # Get selected interface
        selected_interface = interface_combo.get()
        if not selected_interface:
            status_label.config(text="Please select a network interface")
            return

        ip_address, netmask = get_ip_and_subnet(selected_interface)

        if not ip_address or not netmask:
            status_label.config(text="Could not get IP address or netmask")
            return

        # Calculate subnet
        cidr = netmask_to_cidr(netmask)
        subnet = f"{ip_address}/{cidr}"

        # Load MAC database
        mac_db = load_mac_db("oui.csv")

        # Disable scan button
        scan_button.config(state="disabled")
        status_label.config(text="Scanning...")
        
        # Reset and show progress bar
        progress_var.set(0)
        progress_frame.pack(fill=tk.X, pady=5)
        progress_label.config(text=f"Scanning network {subnet}...")

        # Start scan in a separate thread
        scan_thread = threading.Thread(
            target=arp_scan,
            args=(subnet, mac_db, results_var, device_table, status_label, scan_button, progress_frame, progress_bar, progress_label, progress_var)
        )
        scan_thread.daemon = True
        scan_thread.start()

    except Exception as e:
        status_label.config(text=f"Error: {str(e)}")
        scan_button.config(state="normal")
        # Hide progress bar on error
        progress_frame.pack_forget()
