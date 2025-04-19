import psutil
import socket
import time
import tkinter as tk
from tkinter import ttk
from tkinter.ttk import Progressbar
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
from .MacDB import load_mac_db, get_mac_prefix, get_manufacturer_name

UPDATE_DELAY = 1  # Update interval in seconds

# Load MAC Prefix DB (OUI CSV) into a DataFrame
mac_db = load_mac_db()

def get_size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024

def get_mac_address(mac):
    """
    Convert MAC address to colon-separated format if it uses dashes.
    """
    if mac:
        return mac.replace("-", ":")  # Replace dashes with colons
    return "N/A"

def get_device_name(mac):
    """
    Get the manufacturer name from a MAC address.
    """
    mac_colon = get_mac_address(mac)  # Get the MAC address with colons
    if mac_colon:
        mac_parts = mac_colon.split(":")  # Split by colon
        mac_prefix = "".join(mac_parts[:3])  # Join the first 3 parts without colons
        return get_manufacturer_name(mac_prefix)
    return "N/A"

def color_progressbar(progressbar, value):
    """
    Update progress bar color based on the value (0 to 100).
    """
    if value <= 20:
        progressbar['style'] = 'green.Horizontal.TProgressbar'
    elif value <= 40:
        progressbar['style'] = 'yellow.Horizontal.TProgressbar'
    elif value <= 60:
        progressbar['style'] = 'orange.Horizontal.TProgressbar'
    elif value <= 80:
        progressbar['style'] = 'red.Horizontal.TProgressbar'
    else:
        progressbar['style'] = 'purple.Horizontal.TProgressbar'

def update_stats(selected_iface, tree, ax, canvas, download_speeds, upload_speeds, times, start_time, io, cpu_progress, memory_progress, disk_progress, swap_progress, cpu_label, memory_label, disk_label, swap_label, status_label):
    try:
        # Update network stats
        io_2 = psutil.net_io_counters(pernic=True)
        if_addrs = psutil.net_if_addrs()

        # Get existing items in the tree
        existing_items = {tree.item(item)['values'][0]: item for item in tree.get_children()}

        for iface, iface_io in io.items():
            # Calculate speeds
            upload_speed = io_2[iface].bytes_sent - iface_io.bytes_sent
            download_speed = io_2[iface].bytes_recv - iface_io.bytes_recv

            # Get current values from tree if interface exists
            if iface in existing_items:
                current_values = tree.item(existing_items[iface])['values']
                # Keep static values (Interface, IP, MAC, Status) and update network stats
                tree.item(existing_items[iface], values=(
                    current_values[0],  # Interface
                    current_values[1],  # Status
                    f"{get_size(download_speed / UPDATE_DELAY)}/s",  # Speed
                    f"{get_size(upload_speed / UPDATE_DELAY)}/s",  # Upload
                    f"{get_size(download_speed / UPDATE_DELAY)}/s",  # Download
                    current_values[5],  # IP Address
                    current_values[6]   # MAC Address
                ))
            else:
                # For new interfaces, get all information
                ipv4 = ipv6 = mac = None
                for addr in if_addrs.get(iface, []):
                    if addr.family == socket.AF_INET:  # IPv4
                        ipv4 = addr.address
                    elif addr.family == socket.AF_INET6:  # IPv6
                        ipv6 = addr.address
                    elif addr.family == psutil.AF_LINK:  # MAC
                        mac = addr.address

                # Get interface status
                status = "Unknown"
                if iface in psutil.net_if_stats():
                    stats = psutil.net_if_stats()[iface]
                    status = "Connected" if stats.isup else "Disconnected"

                # Insert new item with all information
                tree.insert("", "end", values=(
                    iface,  # Interface
                    status,  # Status
                    f"{get_size(download_speed / UPDATE_DELAY)}/s",  # Speed
                    f"{get_size(upload_speed / UPDATE_DELAY)}/s",  # Upload
                    f"{get_size(download_speed / UPDATE_DELAY)}/s",  # Download
                    ipv4 or "N/A",  # IP Address
                    get_mac_address(mac) or "N/A"  # MAC Address
                ))

            if iface == selected_iface:
                download_speeds.append(download_speed / UPDATE_DELAY)
                upload_speeds.append(upload_speed / UPDATE_DELAY)
                elapsed_time = time.time() - start_time
                times.append(elapsed_time)

        io = io_2

        # Update graph only if we have data points
        ax.clear()
        if times and download_speeds and upload_speeds:
            ax.plot(times, download_speeds, label="Download Speed (bytes/s)", color='blue')
            ax.plot(times, upload_speeds, label="Upload Speed (bytes/s)", color='red')
            ax.legend()
            ax.set_title(f"Network Speeds for {selected_iface} (Download/Upload)")
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Speed (bytes/s)")
            ax.set_facecolor('black')
            
            # Set axis limits with minimum ranges to avoid singular transformation
            x_min, x_max = min(times), max(times)
            y_min, y_max = 0, max(max(download_speeds), max(upload_speeds))
            
            if x_max - x_min < 0.1:  # If time range is too small
                x_max = x_min + 0.1
            if y_max < 0.1:  # If speed range is too small
                y_max = 0.1
                
            ax.set_xlim([x_min, x_max])
            ax.set_ylim([y_min, y_max * 1.1])
        else:
            ax.text(0.5, 0.5, "Select an interface to view network speeds", 
                    horizontalalignment='center', verticalalignment='center')
            ax.set_title("Network Speed Graph")
            ax.set_facecolor('black')
        
        try:
            canvas.draw()
        except Exception as e:
            print(f"Error drawing canvas: {e}")

        # Update system stats
        try:
            cpu_percent = psutil.cpu_percent()
            color_progressbar(cpu_progress, cpu_percent)
            cpu_progress['value'] = cpu_percent
            cpu_label.config(text=f"CPU: {cpu_percent}%")

            memory_percent = psutil.virtual_memory().percent
            color_progressbar(memory_progress, memory_percent)
            memory_progress['value'] = memory_percent
            memory_label.config(text=f"Memory: {memory_percent}%")

            disk_percent = psutil.disk_usage('/').percent
            color_progressbar(disk_progress, disk_percent)
            disk_progress['value'] = disk_percent
            disk_label.config(text=f"Disk: {disk_percent}%")

            swap = psutil.swap_memory()
            swap_percent = swap.percent
            color_progressbar(swap_progress, swap_percent)
            swap_progress['value'] = swap_percent
            swap_label.config(text=f"Swap Used: {swap_percent}%")

            uptime_seconds = time.time() - psutil.boot_time()
            status_label.config(text=f"Uptime: {uptime_seconds // 3600:.0f}h {(uptime_seconds % 3600) // 60:.0f}m")
        except Exception as e:
            print(f"Error updating system stats: {e}")

    except Exception as e:
        print(f"Error in update_stats: {e}")

    return io

def get_network_interfaces():
    """Get all network interfaces and their details."""
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        ipv4 = None
        mac = None
        
        # Get IPv4 and MAC addresses
        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                ipv4 = addr.address
            elif addr.family == psutil.AF_LINK:  # MAC address
                mac = addr.address
        
        # Get interface status
        status = "Unknown"
        if interface in psutil.net_if_stats():
            stats = psutil.net_if_stats()[interface]
            status = "Connected" if stats.isup else "Disconnected"
        
        if ipv4:  # Only add interfaces with IPv4 addresses
            interfaces.append({
                'name': interface,
                'ip': ipv4,
                'mac': mac or "Unknown",
                'status': status
            })
    return interfaces

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

def create_page01(parent_frame):
    # Create main container
    main_container = ttk.Frame(parent_frame)
    main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Add a flag to control the update thread
    is_running = tk.BooleanVar(value=True)

    # Title
    title_label = ttk.Label(
        main_container,
        text="Network Statistics",
        font=("Arial", 18, "bold")
    )
    title_label.pack(pady=(0, 20))

    # Create frames for different sections
    interface_frame = ttk.LabelFrame(main_container, text="Network Interfaces", padding=10)
    interface_frame.pack(fill=tk.X, pady=(0, 10))

    # Create Treeview for network interfaces
    interface_columns = ("Interface", "Status", "Speed", "Upload", "Download", "IP Address", "MAC Address")
    interface_tree = ttk.Treeview(interface_frame, columns=interface_columns, show="headings", height=5)

    # Configure columns
    interface_tree.column("Interface", width=150, anchor="center")
    interface_tree.column("Status", width=100, anchor="center")
    interface_tree.column("Speed", width=100, anchor="center")
    interface_tree.column("Upload", width=100, anchor="center")
    interface_tree.column("Download", width=100, anchor="center")
    interface_tree.column("IP Address", width=150, anchor="center")
    interface_tree.column("MAC Address", width=150, anchor="center")

    # Set headings
    interface_tree.heading("Interface", text="Interface")
    interface_tree.heading("Status", text="Status")
    interface_tree.heading("Speed", text="Speed")
    interface_tree.heading("Upload", text="Upload")
    interface_tree.heading("Download", text="Download")
    interface_tree.heading("IP Address", text="IP Address")
    interface_tree.heading("MAC Address", text="MAC Address")

    # Add scrollbar
    interface_scrollbar = ttk.Scrollbar(interface_frame, orient="vertical", command=interface_tree.yview)
    interface_tree.configure(yscrollcommand=interface_scrollbar.set)

    # Pack interface tree and scrollbar
    interface_tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
    interface_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Create system stats frame
    stats_frame = ttk.LabelFrame(main_container, text="System Statistics")
    stats_frame.pack(fill=tk.X, pady=5)

    # Create progress bars with labels
    progress_frames = []
    progress_bars = []
    labels = []
    
    stats = [
        ("CPU Usage", 'cpu_progress', 'cpu_label'),
        ("Memory Usage", 'memory_progress', 'memory_label'),
        ("Disk Usage", 'disk_progress', 'disk_label'),
        ("Swap Usage", 'swap_progress', 'swap_label')
    ]

    for stat_name, progress_name, label_name in stats:
        frame = ttk.Frame(stats_frame)
        frame.pack(fill=tk.X, padx=5, pady=2)
        
        label = ttk.Label(frame, text=f"{stat_name}: 0%")
        label.pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(frame, length=200, mode='determinate')
        progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        progress_frames.append(frame)
        progress_bars.append(progress)
        labels.append(label)

    # Create graph frame
    graph_frame = ttk.LabelFrame(main_container, text="Network Speed Graph")
    graph_frame.pack(fill=tk.BOTH, expand=True, pady=5)

    # Create interface selection frame
    selection_frame = ttk.Frame(graph_frame)
    selection_frame.pack(fill=tk.X, pady=5)

    # Add interface selection label and combobox
    select_label = ttk.Label(selection_frame, text="Select Interface:")
    select_label.pack(side=tk.LEFT, padx=5)

    interfaces = list(psutil.net_if_addrs().keys())
    # Get default WiFi interface
    default_interface = get_wifi_interface()
    interface_var = tk.StringVar(value=default_interface if default_interface else interfaces[0] if interfaces else "")
    interface_combo = ttk.Combobox(selection_frame, textvariable=interface_var, values=interfaces)
    interface_combo.pack(side=tk.LEFT, padx=5)

    # Create matplotlib figure and canvas
    fig, ax = plt.subplots(figsize=(8, 4))
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # Initialize data storage
    download_speeds = []
    upload_speeds = []
    times = []
    start_time = time.time()
    io = psutil.net_io_counters(pernic=True)

    # Create status label
    status_label = ttk.Label(main_container, text="")
    status_label.pack(fill=tk.X, pady=5)

    def update_interface_info():
        if is_running.get():
            nonlocal io
            io = update_stats(
                interface_var.get(),
                interface_tree,
                ax,
                canvas,
                download_speeds,
                upload_speeds,
                times,
                start_time,
                io,
                progress_bars[0],  # CPU
                progress_bars[1],  # Memory
                progress_bars[2],  # Disk
                progress_bars[3],  # Swap
                labels[0],         # CPU label
                labels[1],         # Memory label
                labels[2],         # Disk label
                labels[3],         # Swap label
                status_label
            )
            # Schedule next update
            main_container.after(UPDATE_DELAY * 1000, update_interface_info)

    # Start the update loop
    update_interface_info()

    # Cleanup when the frame is destroyed
    def on_destroy():
        is_running.set(False)
        plt.close(fig)

    main_container.bind("<Destroy>", lambda e: on_destroy())

    return main_container
