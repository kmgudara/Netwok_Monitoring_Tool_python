import psutil
import win32com.client
import scapy.all as scapy
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Global variable to keep track of packet types
packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "FTP": 0, "Other": 0}
protocol_colors = {
    "TCP": "#90EE90",  # Light Green
    "UDP": "#ADD8E6",  # Light Blue
    "ICMP": "#FFFFE0",  # Light Yellow
    "ARP": "#FFB6C1",  # Light Pink
    "FTP": "#DDA0DD",  # Plum
    "Other": "#D3D3D3",  # Light Gray
}

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

def create_page02(parent_frame):
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
    
    # Get default WiFi interface
    default_interface = get_wifi_interface()
    if default_interface and default_interface in interfaces:
        interface_combo.set(default_interface)
    elif interfaces:
        interface_combo.set(interfaces[0])

    # Create control buttons frame
    control_frame = ttk.Frame(main_container)
    control_frame.pack(fill=tk.X, pady=5)

    start_button = ttk.Button(control_frame, text="Start Capture")
    start_button.pack(side=tk.LEFT, padx=5)

    stop_button = ttk.Button(control_frame, text="Stop Capture")
    stop_button.pack(side=tk.LEFT, padx=5)

    # Create packet display frame
    packet_frame = ttk.LabelFrame(main_container, text="Captured Packets")
    packet_frame.pack(fill=tk.BOTH, expand=True, pady=5)

    # Create Treeview for packet display
    columns = ("Time", "Source", "Destination", "Protocol", "Length")
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

    # Create bottom frame for statistics and pie chart
    bottom_frame = ttk.Frame(main_container)
    bottom_frame.pack(fill=tk.X, pady=5)

    # Create statistics frame (left side)
    stats_frame = ttk.LabelFrame(bottom_frame, text="Packet Statistics")
    stats_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

    # Create progress bars for each protocol
    protocol_bars = {}
    for protocol in packet_counts.keys():
        frame = ttk.Frame(stats_frame)
        frame.pack(fill=tk.X, pady=2)
        
        label = ttk.Label(frame, text=f"{protocol}:")
        label.pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(frame, length=200, mode='determinate')
        progress.pack(side=tk.LEFT, padx=5)
        
        count_label = ttk.Label(frame, text="0")
        count_label.pack(side=tk.LEFT, padx=5)
        
        protocol_bars[protocol] = (progress, count_label)

    # Create matplotlib figure for packet type distribution (right side)
    fig, ax = plt.subplots(figsize=(4, 3))  # Smaller figure size
    canvas = FigureCanvasTkAgg(fig, master=bottom_frame)
    canvas_widget = canvas.get_tk_widget()
    canvas_widget.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Create a stop event for packet capture
    stop_event = threading.Event()
    capture_thread = None

    def update_packet_stats():
        total_packets = sum(packet_counts.values())
        if total_packets > 0:
            for protocol, (progress, count_label) in protocol_bars.items():
                percentage = (packet_counts[protocol] / total_packets) * 100
                progress['value'] = percentage
                count_label.config(text=str(packet_counts[protocol]))

            # Update pie chart
            ax.clear()
            # Draw pie chart without labels
            ax.pie(packet_counts.values(), colors=[protocol_colors[p] for p in packet_counts.keys()])
            ax.set_title("Packet Type Distribution")
            
            # Create legend with protocol names and colors
            legend_elements = [plt.Rectangle((0,0),1,1, facecolor=color) for color in protocol_colors.values()]
            legend_labels = [f"{protocol}" for protocol, color in protocol_colors.items()]
            ax.legend(legend_elements, legend_labels, loc='center left', bbox_to_anchor=(1, 0.5))
            
            # Adjust layout to prevent legend cutoff
            plt.tight_layout()
            canvas.draw()

    def packet_callback(packet):
        if stop_event.is_set():
            return False  # Stop capturing if stop_event is set

        if packet.haslayer(scapy.IP):
            protocol = packet[scapy.IP].proto
            if protocol == 6:  # TCP
                if packet.haslayer(scapy.TCP):
                    if packet[scapy.TCP].dport == 21 or packet[scapy.TCP].sport == 21:
                        packet_type = "FTP"
                    else:
                        packet_type = "TCP"
                else:
                    packet_type = "TCP"
            elif protocol == 17:
                packet_type = "UDP"
            elif protocol == 1:
                packet_type = "ICMP"
            else:
                packet_type = "Other"
        elif packet.haslayer(scapy.ARP):
            packet_type = "ARP"
        else:
            packet_type = "Other"

        packet_counts[packet_type] += 1
        
        # Update packet tree with protocol-based coloring
        item = packet_tree.insert("", 0, values=(
            time.strftime("%H:%M:%S"),
            packet.src if hasattr(packet, 'src') else "N/A",
            packet.dst if hasattr(packet, 'dst') else "N/A",
            packet_type,
            len(packet)
        ))
        
        # Set the background color based on protocol
        packet_tree.tag_configure(packet_type, background=protocol_colors[packet_type])
        packet_tree.item(item, tags=(packet_type,))

        # Update statistics
        update_packet_stats()

    def start_capture():
        if not interface_var.get():
            messagebox.showerror("Error", "Please select an interface")
            return

        # Reset counters and clear tree
        for protocol in packet_counts:
            packet_counts[protocol] = 0
        packet_tree.delete(*packet_tree.get_children())
        
        # Clear stop event
        stop_event.clear()
        
        # Start capture in a separate thread
        global capture_thread
        capture_thread = threading.Thread(target=lambda: scapy.sniff(
            iface=interface_var.get(),
            prn=packet_callback,
            store=0,
            stop_filter=lambda x: stop_event.is_set()
        ))
        capture_thread.daemon = True
        capture_thread.start()

        # Update button states
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

    def stop_capture():
        # Set stop event to stop packet capture
        stop_event.set()
        
        # Wait for capture thread to finish
        if capture_thread and capture_thread.is_alive():
            capture_thread.join(timeout=1.0)
        
        # Update button states
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

    # Bind buttons to functions
    start_button.config(command=start_capture)
    stop_button.config(command=stop_capture)

    # Set initial button states
    stop_button.config(state=tk.DISABLED)

    return main_container
