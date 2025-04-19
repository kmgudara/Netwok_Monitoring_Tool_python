import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil
import os
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io
import socket
import platform
import datetime
import ipaddress
from scapy.all import ARP, Ether, srp
import csv

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

def get_manufacturer_from_mac(mac_address):
    """Get manufacturer name from MAC address using oui.csv database."""
    try:
        # Normalize MAC address (remove separators and convert to uppercase)
        mac = mac_address.replace(':', '').replace('-', '').upper()
        # Get the OUI (first 6 characters)
        oui = mac[:6]
        
        print(f"Looking up manufacturer for MAC prefix: {oui}")
        
        # Read the oui.csv file
        with open('oui.csv', 'r', encoding='utf-8') as f:
            # Skip header
            next(f)
            # Search for the OUI
            for line in f:
                try:
                    assignment, manufacturer = line.strip().split(',', 1)
                    if assignment == oui:
                        manufacturer_name = manufacturer.strip('"')
                        print(f"Found manufacturer: {manufacturer_name} for MAC prefix {oui}")
                        return manufacturer_name
                except Exception as line_error:
                    print(f"Error parsing line in oui.csv: {line_error}")
                    continue
        
        print(f"No manufacturer found for MAC prefix: {oui}")
        return "Unknown"
    except Exception as e:
        print(f"Error getting manufacturer: {str(e)}")
        return "Unknown"

def create_pdf_page(parent_frame):
    """Create a page for generating PDF reports of network statistics."""
    # Create main container
    main_container = ttk.Frame(parent_frame)
    main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Title
    title_label = ttk.Label(
        main_container,
        text="Network Vulnerability Report Generator",
        font=("Arial", 18, "bold")
    )
    title_label.pack(pady=(0, 20))

    # Create interface selection frame
    interface_frame = ttk.LabelFrame(main_container, text="Network Interface", padding=10)
    interface_frame.pack(fill=tk.X, pady=(0, 10))

    interface_label = ttk.Label(interface_frame, text="Select Interface:")
    interface_label.pack(side=tk.LEFT, padx=5)

    interface_var = tk.StringVar()
    interface_combo = ttk.Combobox(interface_frame, textvariable=interface_var)
    interface_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

    # Get network interfaces
    interfaces = [iface for iface in psutil.net_if_addrs().keys()]
    interface_combo['values'] = interfaces
    
    # Get default WiFi interface
    default_interface = get_wifi_interface()
    if default_interface and default_interface in interfaces:
        interface_combo.set(default_interface)
    elif interfaces:
        interface_combo.set(interfaces[0])

    # Create report options frame
    options_frame = ttk.LabelFrame(main_container, text="Report Options", padding=10)
    options_frame.pack(fill=tk.X, pady=(0, 10))

    # Checkboxes for report type selection
    include_vulnerability_var = tk.BooleanVar(value=True)
    include_devices_var = tk.BooleanVar(value=True)
    
    ttk.Checkbutton(
        options_frame, 
        text="Vulnerability Report", 
        variable=include_vulnerability_var
    ).pack(anchor=tk.W, pady=2)
    
    ttk.Checkbutton(
        options_frame, 
        text="Devices in the Network", 
        variable=include_devices_var
    ).pack(anchor=tk.W, pady=2)

    # Create status frame
    status_frame = ttk.LabelFrame(main_container, text="Status", padding=10)
    status_frame.pack(fill=tk.X, pady=(0, 10))

    # Status label
    status_label = ttk.Label(status_frame, text="Ready to generate report")
    status_label.pack(fill=tk.X, pady=5)

    # Progress bar (initially hidden)
    progress_frame = ttk.Frame(status_frame)
    progress_frame.pack(fill=tk.X, pady=5)
    
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(
        progress_frame, 
        variable=progress_var,
        maximum=100,
        mode='determinate'
    )
    progress_bar.pack(fill=tk.X)
    
    # Progress label
    progress_label = ttk.Label(progress_frame, text="")
    progress_label.pack(fill=tk.X)
    
    # Initially hide progress elements
    progress_frame.pack_forget()

    # Create buttons frame
    buttons_frame = ttk.Frame(main_container)
    buttons_frame.pack(fill=tk.X, pady=(0, 10))

    # Generate PDF button
    generate_button = ttk.Button(buttons_frame, text="Generate PDF Report")
    generate_button.pack(side=tk.LEFT, padx=5)

    # Function to get devices in the network
    def get_network_devices(interface):
        """Get devices in the network using ARP scan."""
        devices = []
        
        try:
            # Get the IP address and subnet of the selected interface
            ip_address, netmask = get_ip_and_subnet(interface)
            if not ip_address or not netmask:
                print(f"Could not get IP address or netmask for interface {interface}")
                return devices
            
            # Convert netmask to CIDR notation
            netmask_bits = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            
            # Get the network address
            network = ipaddress.IPv4Network(f"{ip_address}/{netmask_bits}", strict=False)
            
            print(f"Scanning network: {network}")
            
            # Perform ARP scan
            arp = ARP(pdst=str(network))
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send the packet and get the response
            result = srp(packet, timeout=3, verbose=0)[0]
            
            # Process the results
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                
                # Get manufacturer from MAC database
                manufacturer = get_manufacturer_from_mac(mac)
                
                # Get hostname if possible
                hostname = "Unknown"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    pass
                
                # Determine device type based on manufacturer and hostname
                device_type = "Unknown"
                if "router" in hostname.lower() or ip.endswith(".1"):
                    device_type = "Router/Gateway"
                elif "camera" in hostname.lower():
                    device_type = "Camera"
                elif "printer" in hostname.lower() or any(mfg in manufacturer.lower() for mfg in ["hp", "canon", "epson", "brother"]):
                    device_type = "Printer"
                elif "iphone" in hostname.lower() or "apple" in manufacturer.lower():
                    device_type = "iPhone"
                elif "android" in hostname.lower() or "samsung" in manufacturer.lower():
                    device_type = "Android Device"
                elif "laptop" in hostname.lower() or "notebook" in hostname.lower():
                    device_type = "Laptop"
                elif "desktop" in hostname.lower() or "pc" in hostname.lower():
                    device_type = "Desktop"
                elif "smart" in hostname.lower() or "iot" in hostname.lower():
                    device_type = "IoT Device"
                
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "manufacturer": manufacturer,
                    "hostname": hostname,
                    "device_type": device_type,
                    "status": "Active"
                })
                
            print(f"Found {len(devices)} devices on the network")
                
        except Exception as e:
            print(f"Error scanning network: {str(e)}")
            
        return devices

    # Function to scan device for vulnerabilities
    def scan_device_vulnerabilities(device_ip, device_mac, device_hostname):
        """Scan a device for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check if device is responding to ping
            ping_result = os.system(f"ping -n 1 -w 1000 {device_ip} > nul")
            if ping_result != 0:
                vulnerabilities.append({
                    "category": "Connectivity",
                    "status": "Device not responding",
                    "risk_level": "High",
                    "recommendation": "Check if device is powered on and connected to the network"
                })
                return vulnerabilities
            
            # Check for common open ports
            common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((device_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            if open_ports:
                # Determine risk level based on open ports
                high_risk_ports = [23, 445, 3389]  # Telnet, SMB, RDP
                medium_risk_ports = [21, 22, 80, 443]  # FTP, SSH, HTTP, HTTPS
                low_risk_ports = [53, 8080]  # DNS, alternative HTTP
                
                risk_level = "Low"
                if any(port in high_risk_ports for port in open_ports):
                    risk_level = "High"
                elif any(port in medium_risk_ports for port in open_ports):
                    risk_level = "Medium"
                
                vulnerabilities.append({
                    "category": "Open Ports",
                    "status": f"{len(open_ports)} ports open: {', '.join(map(str, open_ports))}",
                    "risk_level": risk_level,
                    "recommendation": "Close unnecessary ports to reduce attack surface"
                })
            
            # Check for outdated software (simulated)
            if device_ip.endswith(".1"):  # Router
                vulnerabilities.append({
                    "category": "Firmware",
                    "status": "Outdated firmware detected",
                    "risk_level": "High",
                    "recommendation": "Update router firmware to the latest version"
                })
            
            # Check for weak passwords (simulated)
            if "router" in device_hostname.lower() or device_ip.endswith(".1"):
                vulnerabilities.append({
                    "category": "Authentication",
                    "status": "Default credentials may be in use",
                    "risk_level": "High",
                    "recommendation": "Change default router credentials immediately"
                })
            
            # Check for encryption (simulated)
            if "router" in device_hostname.lower() or device_ip.endswith(".1"):
                vulnerabilities.append({
                    "category": "Encryption",
                    "status": "WPA2 encryption in use",
                    "risk_level": "Medium",
                    "recommendation": "Consider upgrading to WPA3 for better security"
                })
            
            # Check for IoT devices with known vulnerabilities
            if any(keyword in device_hostname.lower() for keyword in ["camera", "thermostat", "doorbell", "smart", "iot"]):
                vulnerabilities.append({
                    "category": "IoT Security",
                    "status": "IoT device with potential security risks",
                    "risk_level": "Medium",
                    "recommendation": "Update firmware, change default credentials, and isolate on a separate network segment"
                })
            
            # Check for mobile devices
            if any(keyword in device_hostname.lower() for keyword in ["iphone", "android", "mobile", "phone"]):
                vulnerabilities.append({
                    "category": "Mobile Security",
                    "status": "Mobile device detected",
                    "risk_level": "Low",
                    "recommendation": "Ensure device has latest OS updates and security patches installed"
                })
            
            # Check for printers
            if any(keyword in device_hostname.lower() for keyword in ["printer", "hp", "canon", "epson", "brother"]):
                vulnerabilities.append({
                    "category": "Printer Security",
                    "status": "Network printer detected",
                    "risk_level": "Medium",
                    "recommendation": "Update printer firmware, disable unnecessary services, and restrict access to trusted IPs"
                })
            
            # If no vulnerabilities found, add a "secure" entry
            if not vulnerabilities:
                vulnerabilities.append({
                    "category": "Overall Security",
                    "status": "No significant vulnerabilities detected",
                    "risk_level": "Low",
                    "recommendation": "Continue regular security monitoring"
                })
                
        except Exception as e:
            vulnerabilities.append({
                "category": "Scan Error",
                "status": f"Error scanning device: {str(e)}",
                "risk_level": "Unknown",
                "recommendation": "Manual inspection recommended"
            })
            
        return vulnerabilities

    # Function to generate PDF report
    def generate_pdf():
        selected_interface = interface_var.get()
        
        if not selected_interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        if not include_vulnerability_var.get() and not include_devices_var.get():
            messagebox.showerror("Error", "Please select at least one report option")
            return
        
        # Get the downloads folder path
        downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
        default_filename = f"network_vulnerability_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        default_filepath = os.path.join(downloads_path, default_filename)
        
        # Ask user for save location, defaulting to downloads folder
        file_path = filedialog.asksaveasfilename(
            initialfile=default_filename,
            initialdir=downloads_path,
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            title="Save PDF Report"
        )
        
        if not file_path:
            return  # User cancelled
        
        # Show progress bar and update status
        progress_frame.pack(fill=tk.X, pady=5)
        progress_var.set(0)
        progress_label.config(text="Initializing report generation...")
        status_label.config(text="Generating PDF report...")
        generate_button.config(state=tk.DISABLED)
        
        # Run PDF generation in a separate thread to avoid UI freezing
        def pdf_thread():
            try:
                # Update status
                progress_var.set(5)
                progress_label.config(text="Creating PDF document...")
                
                # Create the PDF document
                doc = SimpleDocTemplate(file_path, pagesize=letter)
                styles = getSampleStyleSheet()
                
                # Define custom styles for Nessus-like report
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=24,
                    spaceAfter=30,
                    textColor=colors.HexColor('#1a5276')  # Dark blue
                )
                
                heading1_style = ParagraphStyle(
                    'CustomHeading1',
                    parent=styles['Heading1'],
                    fontSize=18,
                    spaceAfter=12,
                    textColor=colors.HexColor('#1a5276')  # Dark blue
                )
                
                heading2_style = ParagraphStyle(
                    'CustomHeading2',
                    parent=styles['Heading2'],
                    fontSize=14,
                    spaceAfter=8,
                    textColor=colors.HexColor('#2874a6')  # Medium blue
                )
                
                normal_style = ParagraphStyle(
                    'CustomNormal',
                    parent=styles['Normal'],
                    fontSize=10,
                    spaceAfter=6
                )
                
                # Define risk level colors
                risk_colors = {
                    "Critical": colors.HexColor('#c0392b'),  # Red
                    "High": colors.HexColor('#e74c3c'),      # Light red
                    "Medium": colors.HexColor('#f39c12'),    # Orange
                    "Low": colors.HexColor('#27ae60'),       # Green
                    "Info": colors.HexColor('#3498db')       # Blue
                }
                
                elements = []
                
                # Title page
                elements.append(Paragraph("Network Vulnerability Assessment Report", title_style))
                elements.append(Spacer(1, 20))
                
                # Date and time
                elements.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
                elements.append(Spacer(1, 20))
                
                # System information
                progress_var.set(10)
                progress_label.config(text="Adding system information...")
                elements.append(Paragraph("System Information", heading1_style))
                elements.append(Spacer(1, 12))
                
                system_data = [
                    ["Hostname", socket.gethostname()],
                    ["OS", f"{platform.system()} {platform.release()}"],
                    ["Python Version", platform.python_version()],
                    ["CPU Cores", str(psutil.cpu_count())],
                    ["Total Memory", f"{psutil.virtual_memory().total / (1024**3):.2f} GB"]
                ]
                
                system_table = Table(system_data, colWidths=[2*inch, 4*inch])
                system_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#eaf2f8')),  # Light blue
                    ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a5276')),  # Dark blue
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d6eaf8')),  # Very light blue
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                elements.append(system_table)
                elements.append(Spacer(1, 20))
                
                # Network information
                progress_var.set(15)
                progress_label.config(text="Adding network information...")
                elements.append(Paragraph("Network Information", heading1_style))
                elements.append(Spacer(1, 12))
                
                elements.append(Paragraph(f"Selected Interface: {selected_interface}", normal_style))
                elements.append(Spacer(1, 12))
                
                # Get interface addresses
                network_data = []
                addrs = psutil.net_if_addrs().get(selected_interface, [])
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        network_data.append(["IPv4 Address", addr.address])
                        network_data.append(["Netmask", addr.netmask])
                    elif addr.family == socket.AF_LINK:  # MAC address
                        network_data.append(["MAC Address", addr.address])
                
                # Get interface stats
                stats = psutil.net_if_stats().get(selected_interface)
                if stats:
                    network_data.append(["Status", 'Up' if stats.isup else 'Down'])
                    network_data.append(["Speed", f"{stats.speed} Mbps"])
                    network_data.append(["MTU", str(stats.mtu)])
                
                if network_data:
                    network_table = Table(network_data, colWidths=[2*inch, 4*inch])
                    network_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#eaf2f8')),  # Light blue
                        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a5276')),  # Dark blue
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 12),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 10),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d6eaf8')),  # Very light blue
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ]))
                    elements.append(network_table)
                
                elements.append(Spacer(1, 20))
                
                # Get devices in the network first (needed for both vulnerability and devices report)
                progress_var.set(20)
                progress_label.config(text="Scanning network for devices...")
                devices = get_network_devices(selected_interface)
                
                if not devices:
                    progress_label.config(text="No devices found on the network.")
                    status_label.config(text="No devices found on the network. Please check your network connection and try again.")
                    generate_button.config(state=tk.NORMAL)
                    return
                
                if include_vulnerability_var.get():
                    # Vulnerability information
                    progress_var.set(30)
                    progress_label.config(text="Performing vulnerability assessment...")
                    
                    # Scan each device for vulnerabilities
                    all_vulnerabilities = []
                    total_devices = len(devices)
                    
                    for i, device in enumerate(devices):
                        progress_percent = 30 + (i / total_devices * 20)  # 30-50% of progress
                        progress_var.set(progress_percent)
                        progress_label.config(text=f"Scanning device {i+1}/{total_devices}: {device['ip']} ({device['hostname']})")
                        
                        # Scan device for vulnerabilities
                        device_vulnerabilities = scan_device_vulnerabilities(
                            device["ip"], 
                            device["mac"], 
                            device["hostname"]
                        )
                        
                        # Add device info to each vulnerability
                        for vuln in device_vulnerabilities:
                            vuln["device_ip"] = device["ip"]
                            vuln["device_hostname"] = device["hostname"]
                            vuln["device_type"] = device.get("device_type", "Unknown")
                            all_vulnerabilities.append(vuln)
                    
                    # Group vulnerabilities by risk level
                    critical_risk = [v for v in all_vulnerabilities if v["risk_level"] == "Critical"]
                    high_risk = [v for v in all_vulnerabilities if v["risk_level"] == "High"]
                    medium_risk = [v for v in all_vulnerabilities if v["risk_level"] == "Medium"]
                    low_risk = [v for v in all_vulnerabilities if v["risk_level"] == "Low"]
                    info_risk = [v for v in all_vulnerabilities if v["risk_level"] == "Info"]
                    
                    # Detailed Findings
                    elements.append(Paragraph("Detailed Findings", heading1_style))
                    elements.append(Spacer(1, 12))
                    
                    # Sort vulnerabilities by risk level (Critical, High, Medium, Low, Info)
                    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                    all_vulnerabilities.sort(key=lambda x: risk_order.get(x["risk_level"], 5))
                    
                    # Group vulnerabilities by device
                    device_vulnerabilities = {}
                    for vuln in all_vulnerabilities:
                        device_key = f"{vuln['device_hostname']} ({vuln['device_ip']})"
                        if device_key not in device_vulnerabilities:
                            device_vulnerabilities[device_key] = []
                        device_vulnerabilities[device_key].append(vuln)
                    
                    # Add vulnerabilities by device
                    for device_key, device_vulns in device_vulnerabilities.items():
                        elements.append(Paragraph(device_key, heading2_style))
                        elements.append(Spacer(1, 6))
                        
                        # Create vulnerability data table for this device
                        vulnerability_data = [["Category", "Status", "Risk Level", "MAC Address", "Recommendation"]]
                        
                        for vuln in device_vulns:
                            # Get the device's MAC address
                            device_mac = "Unknown"
                            for device in devices:
                                if device["ip"] == vuln["device_ip"]:
                                    device_mac = device["mac"]
                                    break
                                    
                            vulnerability_data.append([
                                vuln["category"],
                                vuln["status"],
                                vuln["risk_level"],
                                device_mac,
                                vuln["recommendation"]
                            ])
                        
                        vulnerability_table = Table(vulnerability_data, colWidths=[1.2*inch, 1.5*inch, 0.8*inch, 1.5*inch, 2*inch])
                        vulnerability_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#eaf2f8')),  # Light blue
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1a5276')),  # Dark blue
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, 0), 12),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 1), (-1, -1), 10),
                            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d6eaf8')),  # Very light blue
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ]))
                        elements.append(vulnerability_table)
                        elements.append(Spacer(1, 12))
                    
                    elements.append(Spacer(1, 20))
                
                if include_devices_var.get():
                    # Devices in the network
                    progress_var.set(80)
                    progress_label.config(text="Adding device information to report...")
                    elements.append(Paragraph("Network Inventory", heading1_style))
                    elements.append(Spacer(1, 12))
                    
                    # Create table header
                    devices_data = [["IP Address", "MAC Address", "Manufacturer", "Device Type", "Hostname", "Status"]]
                    
                    # Add device data with manufacturer information
                    for device in devices:
                        # Get manufacturer from MAC address
                        manufacturer = get_manufacturer_from_mac(device["mac"])
                        print(f"Device {device['ip']} ({device['hostname']}) - MAC: {device['mac']} - Manufacturer: {manufacturer}")
                        devices_data.append([
                            device["ip"],
                            device["mac"],
                            manufacturer,
                            device.get("device_type", "Unknown"),
                            device["hostname"],
                            device["status"]
                        ])
                    
                    devices_table = Table(devices_data, colWidths=[1.2*inch, 1.5*inch, 1.5*inch, 1.2*inch, 1.2*inch, 0.8*inch])
                    devices_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#eaf2f8')),  # Light blue
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1a5276')),  # Dark blue
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 12),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 10),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d6eaf8')),  # Very light blue
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ]))
                    elements.append(devices_table)
                    elements.append(Spacer(1, 20))
                    
                    # Network topology
                    progress_var.set(90)
                    progress_label.config(text="Adding network topology...")
                    elements.append(Paragraph("Network Topology", heading2_style))
                    elements.append(Spacer(1, 12))
                    
                    elements.append(Paragraph("The network topology is a star configuration with a central router connecting all devices. The router provides DHCP services and NAT for internet access.", normal_style))
                    elements.append(Spacer(1, 12))
                    
                    # Create a simple network diagram
                    elements.append(Paragraph("Network Diagram:", normal_style))
                    elements.append(Spacer(1, 6))
                    
                    # Add router first
                    router = next((d for d in devices if "router" in d["hostname"].lower() or d["ip"].endswith(".1")), None)
                    if router:
                        elements.append(Paragraph(f"Router ({router['ip']})", normal_style))
                    else:
                        elements.append(Paragraph("Router (192.168.1.1)", normal_style))
                    
                    # Add other devices
                    for i, device in enumerate(devices):
                        if device != router:
                            prefix = "└── " if i == len(devices) - 1 else "├── "
                            elements.append(Paragraph(f"{prefix}{device['hostname']} ({device['ip']})", normal_style))
                
                # Build the PDF
                progress_var.set(95)
                progress_label.config(text="Building PDF document...")
                doc.build(elements)
                
                # Update status
                progress_var.set(100)
                progress_label.config(text="PDF report generated successfully!")
                status_label.config(text=f"PDF report generated successfully: {file_path}")
                
                # Hide progress bar after a short delay
                def hide_progress():
                    time.sleep(2)
                    progress_frame.pack_forget()
                    generate_button.config(state=tk.NORMAL)
                
                threading.Thread(target=hide_progress, daemon=True).start()
                
            except Exception as e:
                progress_label.config(text=f"Error: {str(e)}")
                status_label.config(text=f"Error generating PDF: {str(e)}")
                messagebox.showerror("Error", f"Failed to generate PDF report: {str(e)}")
                generate_button.config(state=tk.NORMAL)
        
        # Start the PDF generation thread
        threading.Thread(target=pdf_thread, daemon=True).start()

    # Bind button to function
    generate_button.config(command=generate_pdf)

    return main_container 

def test_mac_lookup():
    """Test function to verify MAC address lookup functionality."""
    test_macs = [
        "08:EA:44:00:00:00",  # Extreme Networks
        "F0:EE:7A:00:00:00",  # Apple
        "64:1B:2F:00:00:00",  # Samsung
        "44:D7:7E:00:00:00",  # Bosch
        "68:DD:B7:00:00:00",  # TP-LINK
        "80:9F:F5:19:FF:44"   # Example from user
    ]
    
    print("\n=== MAC Address Manufacturer Lookup Test ===")
    for mac in test_macs:
        manufacturer = get_manufacturer_from_mac(mac)
        print(f"MAC: {mac} -> Manufacturer: {manufacturer}")
    print("===========================================\n")

# Call the test function when the module is imported
test_mac_lookup() 