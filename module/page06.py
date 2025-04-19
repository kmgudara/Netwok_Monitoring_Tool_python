import socket
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from threading import Thread
import time
import sys

# Try importing nmap
try:
    import nmap
except ImportError:
    messagebox.showerror("Error", "python-nmap package is not installed. Please install it using:\npip install python-nmap")
    sys.exit(1)

# Security categories with relevant ports and protocol details
security_protocols = {
    "Application Layer Protocols": {
        "protocols": [
            {"name": "HTTP (Hypertext Transfer Protocol)", "port": 80},
            {"name": "HTTPS (Hypertext Transfer Protocol Secure)", "port": 443},
            {"name": "FTP (File Transfer Protocol)", "port": 21},
            {"name": "SFTP (Secure File Transfer Protocol)", "port": 22},
            {"name": "SMTP (Simple Mail Transfer Protocol)", "port": 25},
            {"name": "IMAP (Internet Message Access Protocol)", "port": 143},
            {"name": "POP3 (Post Office Protocol 3)", "port": 110},
            {"name": "DNS (Domain Name System)", "port": 53},
    {"name": "SNMP (Simple Network Management Protocol)", "port": 161},
        {"name": "Telnet", "port": 23},
            {"name": "SSH (Secure Shell)", "port": 22},
            {"name": "DHCP (Dynamic Host Configuration Protocol)", "port": 67},
            {"name": "TFTP (Trivial File Transfer Protocol)", "port": 69}
        ]
    },
    "Database Protocols": {
        "protocols": [
            {"name": "MySQL", "port": 3306},
            {"name": "PostgreSQL", "port": 5432},
            {"name": "MongoDB", "port": 27017},
            {"name": "Redis", "port": 6379},
        ]
    },
    "Remote Access Protocols": {
        "protocols": [
            {"name": "SSH (Secure Shell)", "port": 22},
            {"name": "Telnet", "port": 23},
            {"name": "RDP (Remote Desktop Protocol)", "port": 3389},
        {"name": "VNC (Virtual Network Computing)", "port": 5900},
        ]
    },
    "Network Services": {
        "protocols": [
            {"name": "DNS (Domain Name System)", "port": 53},
            {"name": "DHCP (Dynamic Host Configuration Protocol)", "port": 67},
            {"name": "SNMP (Simple Network Management Protocol)", "port": 161},
            {"name": "LDAP (Lightweight Directory Access Protocol)", "port": 389},
        ]
    }
}

# Global variables
is_scanning = False
scanner = nmap.PortScanner()
target = socket.gethostbyname(socket.gethostname())

def scan_all_ports(tree, scan_all_button, scan_custom_button, cancel_button, loading_label, remaining_time_label):
    global is_scanning
    is_scanning = True

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for row in tree.get_children():
        tree.delete(row)

    scan_all_button.config(state=tk.DISABLED)
    scan_custom_button.config(state=tk.DISABLED)
    cancel_button.config(state=tk.NORMAL)
    loading_label.config(text="Scanning... Please wait...")
    loading_label.pack(pady=10)
    
    start_time = time.time()
    
    try:
        for port in range(1, 65536):
            if not is_scanning:
                break
            
            try:
                res = scanner.scan(target, str(port))
                state = res['scan'][target]['tcp'][port]['state']
                
                row_values = ("Full Port Scan", "TCP Protocol", port, state, current_time)
                row_id = tree.insert("", "end", values=row_values)
                if state == "open":
                    tree.item(row_id, tags="highlight")
            except nmap.PortScannerError as e:
                tree.insert("", "end", values=("Full Port Scan", "TCP Protocol", port, f"Nmap Error: {str(e)}", current_time))
            except KeyError as e:
                tree.insert("", "end", values=("Full Port Scan", "TCP Protocol", port, f"Data Error: {str(e)}", current_time))
            except Exception as e:
                tree.insert("", "end", values=("Full Port Scan", "TCP Protocol", port, f"Error: {str(e)}", current_time))

            elapsed_time = time.time() - start_time
            remaining_ports = 65535 - port
            estimated_time_left = (elapsed_time / port) * remaining_ports if port > 0 else 0
            
            minutes, seconds = divmod(int(estimated_time_left), 60)
            remaining_time_label.config(text=f"Remaining Time: {minutes}m {seconds}s")
            remaining_time_label.update_idletasks()

        scan_all_button.config(state=tk.NORMAL)
        scan_custom_button.config(state=tk.NORMAL)
        cancel_button.config(state=tk.DISABLED)
        loading_label.config(text="")
        loading_label.pack_forget()
        remaining_time_label.config(text="Scan Complete")
        is_scanning = False

    except Exception as e:
        messagebox.showerror("Scan Error", f"An error occurred during the scan: {str(e)}")
        is_scanning = False
        scan_all_button.config(state=tk.NORMAL)
        scan_custom_button.config(state=tk.NORMAL)
        cancel_button.config(state=tk.DISABLED)
        loading_label.config(text="")
        loading_label.pack_forget()

def scan_custom_port(tree, scan_all_button, scan_custom_button, cancel_button, loading_label, remaining_time_label, custom_port_entry):
    global is_scanning
    is_scanning = True

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    custom_port = custom_port_entry.get()
    
    try:
        custom_port = int(custom_port)
        if custom_port < 1 or custom_port > 65535:
            raise ValueError("Port number must be between 1 and 65535.")
    except ValueError as e:
        messagebox.showerror("Invalid Input", f"Error: {str(e)}")
        return
    
    for row in tree.get_children():
        tree.delete(row)

    scan_all_button.config(state=tk.DISABLED)
    scan_custom_button.config(state=tk.DISABLED)
    cancel_button.config(state=tk.NORMAL)
    loading_label.config(text="Scanning... Please wait...")
    loading_label.pack(pady=10)
    
    start_time = time.time()
    
    try:
        res = scanner.scan(target, str(custom_port))
        state = res['scan'][target]['tcp'][custom_port]['state']
        
        row_values = ("Custom Port Scan", "Custom Protocol", custom_port, state, current_time)
        row_id = tree.insert("", "end", values=row_values)
        if state == "open":
            tree.item(row_id, tags="highlight")
        
    except nmap.PortScannerError as e:
        tree.insert("", "end", values=("Custom Port Scan", "Custom Protocol", custom_port, f"Nmap Error: {str(e)}", current_time))
    except KeyError as e:
        tree.insert("", "end", values=("Custom Port Scan", "Custom Protocol", custom_port, f"Data Error: {str(e)}", current_time))
    except Exception as e:
        tree.insert("", "end", values=("Custom Port Scan", "Custom Protocol", custom_port, f"Error: {str(e)}", current_time))

    elapsed_time = time.time() - start_time
    minutes, seconds = divmod(int(elapsed_time), 60)
    remaining_time_label.config(text=f"Scan Time: {minutes}m {seconds}s")
    
    scan_all_button.config(state=tk.NORMAL)
    scan_custom_button.config(state=tk.NORMAL)
    cancel_button.config(state=tk.DISABLED)
    loading_label.config(text="")
    loading_label.pack_forget()
    remaining_time_label.config(text="Scan Complete")
    is_scanning = False

def cancel_scan(scan_all_button, scan_custom_button, cancel_button, loading_label, remaining_time_label):
    global is_scanning
    is_scanning = False
    
    cancel_button.config(state=tk.DISABLED)
    scan_all_button.config(state=tk.NORMAL)
    scan_custom_button.config(state=tk.NORMAL)
    loading_label.config(text="Scan Cancelled.")
    remaining_time_label.config(text="Scan Cancelled.")
    loading_label.pack_forget()

# Function to run the scan in a separate thread
def start_scan_all_thread():
    thread = Thread(target=scan_all_ports)
    thread.daemon = True  # Allow thread to be terminated when the program ends
    thread.start()

# Function to run the custom scan in a separate thread
def start_scan_custom_thread():
    thread = Thread(target=scan_custom_port)
    thread.daemon = True  # Allow thread to be terminated when the program ends
    thread.start()

def create_page06(parent_frame):
    # Create main container
    main_container = ttk.Frame(parent_frame)
    main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Create a frame for the scan controls
    control_frame = ttk.Frame(main_container)
    control_frame.pack(fill=tk.X, pady=5)

    # Create a label for the loading message
    loading_label = ttk.Label(control_frame, text="", font=("Arial", 12, "italic"), foreground="red")
    loading_label.pack(pady=10)  # Pack it initially

    # Create a label to show remaining time
    remaining_time_label = ttk.Label(control_frame, text="Remaining Time: 0m 0s", font=("Arial", 12), foreground="blue")
    remaining_time_label.pack(pady=10)

    # Create buttons
    scan_all_button = ttk.Button(control_frame, text="Start Normal Port Scan")
    scan_all_button.pack(pady=10)

    scan_custom_button = ttk.Button(control_frame, text="Start Custom Port Scan")
    scan_custom_button.pack(pady=10)

    cancel_button = ttk.Button(control_frame, text="Cancel Scan", state=tk.DISABLED)
    cancel_button.pack(pady=10)

    # Create custom port input
    custom_port_frame = ttk.Frame(control_frame)
    custom_port_frame.pack(pady=5)
    
    ttk.Label(custom_port_frame, text="Custom Port:").pack(side=tk.LEFT, padx=5)
    custom_port_entry = ttk.Entry(custom_port_frame, width=10)
    custom_port_entry.pack(side=tk.LEFT, padx=5)

    # Create Treeview for results
    tree_frame = ttk.Frame(main_container)
    tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)

    # Create Treeview with scrollbars
    tree = ttk.Treeview(tree_frame, columns=("Scan Type", "Protocol", "Port", "Status", "Time"), show="headings")
    
    # Configure columns with better widths
    tree.heading("Scan Type", text="Scan Type")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Port", text="Port")
    tree.heading("Status", text="Status")
    tree.heading("Time", text="Time")
    
    # Set column widths
    tree.column("Scan Type", width=150, minwidth=100)
    tree.column("Protocol", width=150, minwidth=100)
    tree.column("Port", width=80, minwidth=60)
    tree.column("Status", width=100, minwidth=80)
    tree.column("Time", width=150, minwidth=100)
    
    # Add scrollbars
    y_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
    x_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
    tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
    
    # Pack the Treeview and scrollbars
    tree.grid(row=0, column=0, sticky="nsew")
    y_scrollbar.grid(row=0, column=1, sticky="ns")
    x_scrollbar.grid(row=1, column=0, sticky="ew")
    
    # Configure grid weights
    tree_frame.grid_columnconfigure(0, weight=1)
    tree_frame.grid_rowconfigure(0, weight=1)

    # Configure tag for highlighting open ports
    tree.tag_configure("highlight", background="lightgreen")

    # Bind button commands
    scan_all_button.config(command=lambda: Thread(target=scan_all_ports, args=(tree, scan_all_button, scan_custom_button, cancel_button, loading_label, remaining_time_label), daemon=True).start())
    scan_custom_button.config(command=lambda: Thread(target=scan_custom_port, args=(tree, scan_all_button, scan_custom_button, cancel_button, loading_label, remaining_time_label, custom_port_entry), daemon=True).start())
    cancel_button.config(command=lambda: cancel_scan(scan_all_button, scan_custom_button, cancel_button, loading_label, remaining_time_label))

    return main_container
