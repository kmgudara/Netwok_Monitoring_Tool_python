import os
import nmap
import psutil
import socket
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import ipaddress

def get_ip_and_subnet(interface_name):
    """Get IP address and subnet mask for the selected interface."""
    try:
        addrs = psutil.net_if_addrs().get(interface_name, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address, addr.netmask
    except Exception as e:
        print(f"Error getting IP and subnet: {str(e)}")
    return None, None

def get_network_interfaces():
    """Get list of network interfaces with their IP addresses and subnet masks."""
    interfaces = psutil.net_if_addrs()
    interface_list = []
    for interface in interfaces:
        for addr in interfaces[interface]:
            if addr.family == socket.AF_INET:  # Check for IPv4 addresses
                subnet_mask = None
                for snm in interfaces[interface]:
                    if snm.family == socket.AF_INET and snm.address == addr.address:
                        subnet_mask = snm.netmask
                interface_list.append({'name': interface, 'ip': addr.address, 'subnet_mask': subnet_mask})
    return interface_list

def scan_network(network):
    """Scan the network and return online IP addresses."""
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    online_ips = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return online_ips

def get_device_details(ip):
    """Get device details using Nmap."""
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O -sV')
    device_info = {}
    if 'osmatch' in nm[ip]:
        device_info['Operating System'] = nm[ip]['osmatch']
    if 'tcp' in nm[ip]:
        device_info['Services'] = [{
            'Port': port,
            'Service': nm[ip]['tcp'][port].get('name', 'N/A'),
            'Version': nm[ip]['tcp'][port].get('version', 'N/A')
        } for port in nm[ip]['tcp']]
    return device_info

def create_page05(parent_frame):
    """Create the network and vulnerability scanner page."""
    # Create main container
    main_container = ttk.Frame(parent_frame)
    main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Title
    title_label = ttk.Label(
        main_container,
        text="Vulnerability Scanner",
        font=("Arial", 18, "bold")
    )
    title_label.pack(pady=(0, 20))

    # Interface Selection Frame
    interface_frame = ttk.LabelFrame(main_container, text="Network Interface Selection", padding=10)
    interface_frame.pack(fill=tk.X, pady=(0, 10))

    # Interface Combobox
    interfaces = get_network_interfaces()
    interface_names = [i['name'] for i in interfaces]
    interface_combo = ttk.Combobox(interface_frame, values=interface_names, state="readonly", width=40)
    interface_combo.pack(pady=(0, 10))

    # Interface Details Listbox
    interface_listbox = tk.Listbox(interface_frame, height=5, font=("Arial", 10))
    interface_listbox.pack(fill=tk.X)
    for idx, interface in enumerate(interfaces, 1):
        interface_listbox.insert(tk.END, f"{idx}. {interface['name']} (IP: {interface['ip']})")

    # Online Devices Frame
    devices_frame = ttk.LabelFrame(main_container, text="Online Devices", padding=10)
    devices_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    # Online Devices Listbox
    ip_listbox = tk.Listbox(devices_frame, height=8, font=("Arial", 10))
    ip_listbox.pack(fill=tk.BOTH, expand=True)

    # Scan Results Frame
    results_frame = ttk.LabelFrame(main_container, text="Scan Results", padding=10)
    results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    # Results Treeview
    columns = ("Detail", "Service", "Version")
    result_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=10)
    
    # Configure columns
    result_tree.heading("Detail", text="Detail")
    result_tree.heading("Service", text="Service")
    result_tree.heading("Version", text="Version")
    
    result_tree.column("Detail", width=200, anchor="w")
    result_tree.column("Service", width=200, anchor="w")
    result_tree.column("Version", width=200, anchor="w")

    # Add scrollbar
    scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=result_tree.yview)
    result_tree.configure(yscrollcommand=scrollbar.set)

    # Pack tree and scrollbar
    result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Status Label
    status_label = ttk.Label(main_container, text="", font=("Arial", 10))
    status_label.pack(pady=(0, 10))

    # Create progress frames (initially hidden)
    network_progress_frame = ttk.Frame(main_container)
    network_progress_frame.pack(fill=tk.X, pady=5)
    network_progress_frame.pack_forget()  # Hide initially
    
    vuln_progress_frame = ttk.Frame(main_container)
    vuln_progress_frame.pack(fill=tk.X, pady=5)
    vuln_progress_frame.pack_forget()  # Hide initially
    
    # Create progress bars
    network_progress_var = tk.DoubleVar()
    network_progress_bar = ttk.Progressbar(
        network_progress_frame, 
        variable=network_progress_var,
        maximum=100,
        mode='determinate'
    )
    network_progress_bar.pack(fill=tk.X, padx=5, pady=5)
    
    vuln_progress_var = tk.DoubleVar()
    vuln_progress_bar = ttk.Progressbar(
        vuln_progress_frame, 
        variable=vuln_progress_var,
        maximum=100,
        mode='determinate'
    )
    vuln_progress_bar.pack(fill=tk.X, padx=5, pady=5)
    
    # Create progress labels
    network_progress_label = ttk.Label(network_progress_frame, text="Scanning network...")
    network_progress_label.pack(pady=(0, 5))
    
    vuln_progress_label = ttk.Label(vuln_progress_frame, text="Scanning for vulnerabilities...")
    vuln_progress_label.pack(pady=(0, 5))

    # Buttons Frame
    button_frame = ttk.Frame(main_container)
    button_frame.pack(fill=tk.X, pady=(0, 10))

    # Network Scan Button
    scan_button = ttk.Button(
        button_frame,
        text="Scan Network",
        command=lambda: start_network_scan(
            interface_combo,
            interfaces,
            ip_listbox,
            status_label,
            scan_button,
            network_progress_frame,
            network_progress_bar,
            network_progress_label,
            network_progress_var
        )
    )
    scan_button.pack(side=tk.LEFT, padx=5)

    # Vulnerability Scan Button
    vuln_scan_button = ttk.Button(
        button_frame,
        text="Scan Vulnerabilities",
        command=lambda: start_vulnerability_scan(
            ip_listbox,
            result_tree,
            status_label,
            vuln_scan_button,
            vuln_progress_frame,
            vuln_progress_bar,
            vuln_progress_label,
            vuln_progress_var
        )
    )
    vuln_scan_button.pack(side=tk.LEFT, padx=5)

    return main_container

def start_network_scan(interface_combo, interfaces, ip_listbox, status_label, scan_button, progress_frame, progress_bar, progress_label, progress_var):
    """Start the network scanning process."""
    try:
        # Get the IP address and subnet of the selected interface
        ip_address, netmask = get_ip_and_subnet(interface_combo.get())
        if not ip_address or not netmask:
            status_label.config(text="Could not get IP address or netmask")
            return

        # Convert netmask to CIDR notation
        netmask_bits = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        
        # Get the network address
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask_bits}", strict=False)
        
        # Disable scan button and show progress
        scan_button.config(state="disabled")
        progress_frame.pack(fill=tk.X, pady=5)
        progress_var.set(0)
        progress_label.config(text="Starting network scan...")
        
        def scan():
            try:
                # Get list of IPs to scan
                ip_list = list(network.hosts())
                total_ips = len(ip_list)
                online_ips = []
                
                # Scan each IP
                for i, ip in enumerate(ip_list):
                    # Update progress from 0% to 50% based on IPs scanned
                    progress = (i + 1) / total_ips * 50 if total_ips > 0 else 50
                    progress_var.set(progress)
                    progress_label.config(text=f"Scanning IP {i+1} of {total_ips}")
                    
                    # Check if IP is online
                    if os.system(f"ping -n 1 -w 1000 {ip} > nul") == 0:
                        online_ips.append(str(ip))
                
                # Process results
                progress_label.config(text="Processing scan results...")
                
                ip_listbox.delete(0, tk.END)
                if online_ips:
                    total_ips = len(online_ips)
                    for i, ip in enumerate(online_ips):
                        ip_listbox.insert(tk.END, ip)
                        
                        # Update progress from 50% to 100% based on IPs processed
                        progress = 50 + (i + 1) / total_ips * 50 if total_ips > 0 else 100
                        progress_var.set(progress)
                        progress_label.config(text=f"Processing device {i+1} of {total_ips}")
                        
                    status_label.config(text=f"Found {len(online_ips)} online devices")
                else:
                    progress_var.set(100)
                    progress_label.config(text="No online devices found")
                    status_label.config(text="No online devices found")
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
        
        threading.Thread(target=scan, daemon=True).start()
    except Exception as e:
        status_label.config(text=f"Error: {str(e)}")
        scan_button.config(state="normal")
        progress_frame.pack_forget()

def start_vulnerability_scan(ip_listbox, result_tree, status_label, vuln_scan_button, progress_frame, progress_bar, progress_label, progress_var):
    """Start the vulnerability scanning process."""
    try:
        selected_ip = ip_listbox.get(tk.ACTIVE)
        if not selected_ip:
            status_label.config(text="Please select an IP address from the list")
            return

        vuln_scan_button.config(state="disabled")
        status_label.config(text="Scanning for vulnerabilities...")
        
        # Reset and show progress bar
        progress_var.set(0)
        progress_frame.pack(fill=tk.X, pady=5)
        progress_label.config(text=f"Initializing vulnerability scan for {selected_ip}...")

        def scan():
            try:
                # Update progress to 10% - starting scan
                progress_var.set(10)
                progress_label.config(text=f"Scanning {selected_ip} for vulnerabilities...")
                
                # Clear previous results
                for item in result_tree.get_children():
                    result_tree.delete(item)

                # Get device details
                device_details = get_device_details(selected_ip)
                
                # Update progress to 50% - scan complete, processing results
                progress_var.set(50)
                progress_label.config(text="Processing vulnerability scan results...")

                # Display Operating System information
                if 'Operating System' in device_details:
                    result_tree.insert('', tk.END, values=("Operating System", device_details['Operating System'], ""))

                # Display Services information
                if 'Services' in device_details:
                    services = device_details['Services']
                    total_services = len(services)
                    
                    for i, service in enumerate(services):
                        result_tree.insert('', tk.END, values=(
                            f"Port {service['Port']}",
                            service['Service'],
                            service['Version']
                        ))
                        
                        # Update progress from 50% to 100% based on services processed
                        progress = 50 + (i + 1) / total_services * 50 if total_services > 0 else 100
                        progress_var.set(progress)
                        progress_label.config(text=f"Processing service {i+1} of {total_services}")

                status_label.config(text="Vulnerability scan completed")
            except Exception as e:
                status_label.config(text=f"Error during vulnerability scan: {str(e)}")
            finally:
                # Set progress to 100% and hide after a short delay
                progress_var.set(100)
                progress_label.config(text="Vulnerability scan completed!")
                
                # Hide progress bar after a short delay
                def hide_progress():
                    progress_frame.after(1000, progress_frame.pack_forget)
                
                progress_frame.after(1000, hide_progress)
                vuln_scan_button.config(state="normal")

        threading.Thread(target=scan, daemon=True).start()

    except Exception as e:
        status_label.config(text=f"Error: {str(e)}")
        vuln_scan_button.config(state="normal")
        progress_frame.pack_forget()

if __name__ == "__main__":
    main_gui()
