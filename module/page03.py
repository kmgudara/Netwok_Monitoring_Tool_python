import psutil
import win32com.client
import scapy.all as scapy
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import threading
import time
import collections

# Global variable to keep track of packet counts by source and destination
packet_counts = {}

# Create a stop event for packet capture
stop_event = threading.Event()
mirror_thread = None


def get_windows_interfaces():
    """Get a list of available network interfaces with human-readable names."""
    wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    connection = wmi.ConnectServer(".", "root\\CIMV2")
    query = "SELECT * FROM Win32_NetworkAdapter"
    adapters = connection.ExecQuery(query)
    interfaces = psutil.net_if_addrs()
    readable_interfaces = [iface for iface in interfaces if "Ethernet" in iface or "Wi-Fi" in iface]
    return readable_interfaces


def packet_callback(packet, treeview, stats_tree, stop_event, root):
    """Callback function to process each captured packet."""
    global packet_counts
    packet_info = []
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        packet_length = len(packet)
    else:
        src_ip, dst_ip = "Unknown", "Unknown"
        packet_length = 0

    # Update packet counts with proper tuple structure
    if (src_ip, dst_ip) in packet_counts:
        current_packets, current_bytes = packet_counts[(src_ip, dst_ip)]
        packet_counts[(src_ip, dst_ip)] = (current_packets + 1, current_bytes + packet_length)
    else:
        packet_counts[(src_ip, dst_ip)] = (1, packet_length)

    packet_info.extend([f"{src_ip} -> {dst_ip}", timestamp])
    root.after(0, lambda: treeview.insert("", tk.END, values=packet_info))
    root.after(0, lambda: update_stats_table(stats_tree, root))


def sort_stats_tree(tree, col):
    """Sort the statistics tree by the specified column."""
    try:
        # Get all items and their values
        items = [(tree.set(item, col), item) for item in tree.get_children('')]
        
        # Handle numeric columns (Packets and Bytes)
        if col in ["Packets", "Bytes"]:
            # Remove formatting and convert to numbers
            def get_numeric_value(value):
                if col == "Packets":
                    return int(value.replace(",", ""))
                else:  # Bytes
                    # Convert human-readable format to bytes
                    value = value.strip()
                    if "TB" in value:
                        return float(value.replace(" TB", "")) * 1024**4
                    elif "GB" in value:
                        return float(value.replace(" GB", "")) * 1024**3
                    elif "MB" in value:
                        return float(value.replace(" MB", "")) * 1024**2
                    elif "KB" in value:
                        return float(value.replace(" KB", "")) * 1024
                    else:
                        return float(value.replace(" B", ""))
            
            # Sort with numeric values
            items.sort(key=lambda x: get_numeric_value(x[0]), reverse=True)
        else:
            # Sort string values (Source and Destination)
            items.sort(key=lambda x: x[0].lower(), reverse=True)
        
        # Reorder items in the tree
        for index, (val, item) in enumerate(items):
            tree.move(item, '', index)
            
    except Exception as e:
        print(f"Error sorting tree: {e}")


def update_stats_table(stats_tree, root):
    """Update the statistics table with the latest packet counts sorted in descending order."""
    try:
        # Clear existing items
        stats_tree.delete(*stats_tree.get_children())
        
        # Sort packet counts by count in descending order (highest to lowest)
        sorted_counts = sorted(packet_counts.items(), key=lambda x: x[1][0], reverse=True)
        
        # Configure tag colors for different traffic levels
        stats_tree.tag_configure("very_high", background="#FFE6E6")  # Light red
        stats_tree.tag_configure("high", background="#FFF2E6")      # Light orange
        stats_tree.tag_configure("medium_high", background="#FFF9E6") # Light yellow
        stats_tree.tag_configure("medium", background="#E6FFE6")    # Light green
        stats_tree.tag_configure("normal", background="#E6F3FF")    # Light blue
        
        # Insert sorted items with appropriate tags
        for (src, dst), (packets, bytes) in sorted_counts:
            tag = "normal"
            if packets > 2000:
                tag = "very_high"
                root.after(0, lambda: messagebox.showwarning("Alert", f"Extreme traffic detected between {src} and {dst}: more than 2000 packets!"))
            elif packets > 1500:
                tag = "high"
                root.after(0, lambda: messagebox.showwarning("Alert", f"High traffic detected between {src} and {dst}: {packets} packets!"))
            elif packets > 1000:
                tag = "medium_high"
            elif packets > 500:
                tag = "medium"
            
            # Format the values for display
            formatted_packets = f"{packets:,}"
            formatted_bytes = get_size(bytes)
            
            # Insert with formatted values and tag
            stats_tree.insert("", "end", values=(
                src,
                dst,
                formatted_packets,
                formatted_bytes
            ), tags=(tag,))
            
        # Force sort by packets column in descending order
        sort_stats_tree(stats_tree, "Packets")
            
    except Exception as e:
        print(f"Error updating stats table: {e}")


def get_size(bytes):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024
    return f"{bytes:.2f} TB"


def capture_packets(interface, treeview, stats_tree, stop_event, root):
    """Capture live packets on the selected network interface."""
    try:
        scapy.sniff(iface=interface, prn=lambda packet: packet_callback(packet, treeview, stats_tree, stop_event, root), store=0, stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        print(f"An error occurred: {e}")


def start_capture(treeview, stop_event, interface_label, stats_tree, root):
    """Start capturing packets on the selected interface."""
    selected_interface = interface_label.get()
    if selected_interface:
        stop_event.clear()
        capture_thread = threading.Thread(target=capture_packets, args=(selected_interface, treeview, stats_tree, stop_event, root))
        capture_thread.daemon = True
        capture_thread.start()
    else:
        messagebox.showerror("Error", "Please select a valid interface!")


def stop_capture(stop_event):
    """Stop packet capture."""
    stop_event.set()


def create_page03(parent_frame):
    # Create the main container
    main_container = ttk.Frame(parent_frame)
    main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Create interface selection frame
    interface_frame = ttk.Frame(main_container)
    interface_frame.pack(fill=tk.X, pady=5)

    interface_label = ttk.Label(interface_frame, text="Select Interface:")
    interface_label.pack(side=tk.LEFT, padx=5)

    interface_var = tk.StringVar()
    interface_combo = ttk.Combobox(interface_frame, textvariable=interface_var)
    interface_combo.pack(side=tk.LEFT, padx=5)

    # Get network interfaces
    interfaces = [iface for iface in psutil.net_if_addrs().keys()]
    interface_combo['values'] = interfaces
    if interfaces:
        interface_combo.set(interfaces[0])

    # Create control buttons frame
    control_frame = ttk.Frame(main_container)
    control_frame.pack(fill=tk.X, pady=5)

    start_button = ttk.Button(control_frame, text="Start Mirroring")
    start_button.pack(side=tk.LEFT, padx=5)

    stop_button = ttk.Button(control_frame, text="Stop Mirroring")
    stop_button.pack(side=tk.LEFT, padx=5)

    resume_button = ttk.Button(control_frame, text="Resume Mirroring", state=tk.DISABLED)
    resume_button.pack(side=tk.LEFT, padx=5)

    # Create packet display frame
    packet_frame = ttk.LabelFrame(main_container, text="Mirrored Packets")
    packet_frame.pack(fill=tk.BOTH, expand=True, pady=5)

    # Create Treeview for packet display
    columns = ("Time", "Source", "Destination", "Protocol", "Length", "Info")
    packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings")

    # Define headings
    for col in columns:
        packet_tree.heading(col, text=col)
        packet_tree.column(col, anchor=tk.CENTER)

    # Add scrollbar
    scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=packet_tree.yview)
    packet_tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    packet_tree.pack(fill=tk.BOTH, expand=True)

    # Create statistics frame
    stats_frame = ttk.LabelFrame(main_container, text="Mirroring Statistics")
    stats_frame.pack(fill=tk.X, pady=5)

    # Create Treeview for statistics with sortable columns
    stats_columns = ("Source", "Destination", "Packets", "Bytes")
    stats_tree = ttk.Treeview(stats_frame, columns=stats_columns, show="headings")

    # Define headings for stats with sorting capability
    for col in stats_columns:
        stats_tree.heading(col, text=col, command=lambda c=col: sort_stats_tree(stats_tree, c))
        stats_tree.column(col, anchor=tk.CENTER, width=150)  # Set default width

    # Add scrollbar for stats
    stats_scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=stats_tree.yview)
    stats_tree.configure(yscrollcommand=stats_scrollbar.set)
    stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    stats_tree.pack(fill=tk.BOTH, expand=True)

    def update_stats():
        # Clear existing stats
        for item in stats_tree.get_children():
            stats_tree.delete(item)

        # Update with current stats
        for (src, dst), (packets, bytes) in packet_counts.items():
            stats_tree.insert("", "end", values=(src, dst, packets, bytes))

        # Schedule next update
        parent_frame.after(1000, update_stats)

    def packet_callback(packet):
        if stop_event.is_set():
            return False

        try:
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                length = len(packet)

                # Limit packet storage to prevent memory issues
                max_stored_packets = 1000
                if len(packet_tree.get_children()) >= max_stored_packets:
                    # Remove oldest entry
                    oldest = packet_tree.get_children()[0]
                    packet_tree.delete(oldest)

                # Update packet counts with memory management
                if (src, dst) not in packet_counts:
                    if len(packet_counts) >= max_stored_packets:
                        # Remove oldest entry
                        oldest_pair = next(iter(packet_counts))
                        del packet_counts[oldest_pair]
                    packet_counts[(src, dst)] = [0, 0]
                
                packet_counts[(src, dst)][0] += 1
                packet_counts[(src, dst)][1] += length

                # Get protocol name
                protocol_name = {
                    6: "TCP",
                    17: "UDP",
                    1: "ICMP"
                }.get(protocol, "Other")

                # Add packet info with protocol-specific details
                packet_info = {
                    "time": time.strftime("%H:%M:%S"),
                    "src": src,
                    "dst": dst,
                    "protocol": protocol_name,
                    "length": length,
                    "info": ""
                }

                # Add protocol-specific information
                if protocol_name == "TCP" and packet.haslayer(scapy.TCP):
                    tcp = packet[scapy.TCP]
                    packet_info["info"] = f"Port {tcp.sport} → {tcp.dport}"
                    if tcp.flags:
                        flag_names = []
                        if tcp.flags.S: flag_names.append("SYN")
                        if tcp.flags.A: flag_names.append("ACK")
                        if tcp.flags.F: flag_names.append("FIN")
                        if tcp.flags.R: flag_names.append("RST")
                        if tcp.flags.P: flag_names.append("PSH")
                        packet_info["info"] += f" [{' '.join(flag_names)}]"
                elif protocol_name == "UDP" and packet.haslayer(scapy.UDP):
                    udp = packet[scapy.UDP]
                    packet_info["info"] = f"Port {udp.sport} → {udp.dport}"
                elif protocol_name == "ICMP" and packet.haslayer(scapy.ICMP):
                    icmp = packet[scapy.ICMP]
                    packet_info["info"] = f"Type: {icmp.type}, Code: {icmp.code}"

                # Update packet tree with color coding
                item = packet_tree.insert("", 0, values=(
                    packet_info["time"],
                    packet_info["src"],
                    packet_info["dst"],
                    packet_info["protocol"],
                    packet_info["length"],
                    packet_info["info"]
                ))

                # Color code based on protocol
                color = {
                    "TCP": "#E8F5E9",  # Light green
                    "UDP": "#E3F2FD",  # Light blue
                    "ICMP": "#FFF3E0", # Light orange
                    "Other": "#F5F5F5" # Light gray
                }.get(protocol_name)
                
                if color:
                    packet_tree.tag_configure(protocol_name, background=color)
                    packet_tree.item(item, tags=(protocol_name,))

        except Exception as e:
            print(f"Error processing packet: {e}")
            return True  # Continue capturing despite errors

        return True  # Continue capturing

    def start_mirroring():
        if not interface_var.get():
            messagebox.showerror("Error", "Please select an interface")
            return

        # Reset counters
        packet_counts.clear()
        packet_tree.delete(*packet_tree.get_children())
        
        # Clear stop event
        stop_event.clear()
        
        # Start mirroring in a separate thread
        global mirror_thread
        mirror_thread = threading.Thread(target=lambda: scapy.sniff(
            iface=interface_var.get(),
            prn=packet_callback,
            store=0,
            stop_filter=lambda x: stop_event.is_set()
        ))
        mirror_thread.daemon = True
        mirror_thread.start()

        # Start stats updates
        update_stats()

        # Update button states
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
        resume_button.config(state=tk.DISABLED)

    def stop_mirroring():
        # Set stop event to stop packet capture
        stop_event.set()
        
        # Wait for mirror thread to finish
        global mirror_thread
        if mirror_thread and mirror_thread.is_alive():
            mirror_thread.join(timeout=1.0)
        
        # Update button states
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
        resume_button.config(state=tk.NORMAL)

    def resume_mirroring():
        if not interface_var.get():
            messagebox.showerror("Error", "Please select an interface")
            return

        # Clear stop event
        stop_event.clear()
        
        # Start mirroring in a separate thread
        global mirror_thread
        mirror_thread = threading.Thread(target=lambda: scapy.sniff(
            iface=interface_var.get(),
            prn=packet_callback,
            store=0,
            stop_filter=lambda x: stop_event.is_set()
        ))
        mirror_thread.daemon = True
        mirror_thread.start()

        # Update button states
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
        resume_button.config(state=tk.DISABLED)

    # Bind buttons to functions
    start_button.config(command=start_mirroring)
    stop_button.config(command=stop_mirroring)
    resume_button.config(command=resume_mirroring)

    return main_container


if __name__ == "__main__":
    main()
