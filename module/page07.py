import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import subprocess
import threading
import platform
import time

def create_page07(parent_frame):
    # Create main container
    main_container = ttk.Frame(parent_frame)
    main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Title
    title_label = ttk.Label(
        main_container,
        text="Traceroute (IPv4)",
        font=("Arial", 18, "bold")
    )
    title_label.pack(pady=(0, 20))

    # URL Input Frame
    url_frame = ttk.Frame(main_container)
    url_frame.pack(fill=tk.X, pady=(0, 10))

    url_label = ttk.Label(url_frame, text="Enter Your Website Name:", font=("Arial", 11))
    url_label.pack(side=tk.LEFT, padx=(0, 10))

    url_entry = ttk.Entry(url_frame, font=("Arial", 10))
    url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
    url_entry.insert(0, "e.g., www.google.com")
    url_entry.bind("<FocusIn>", lambda e: url_entry.delete(0, tk.END) if url_entry.get() == "e.g., www.google.com" else None)
    url_entry.bind("<FocusOut>", lambda e: url_entry.insert(0, "e.g., www.google.com") if not url_entry.get() else None)

    # IP Address Display
    ip_frame = ttk.Frame(main_container)
    ip_frame.pack(fill=tk.X, pady=(0, 10))

    ip_label = ttk.Label(ip_frame, text="This is Your Website IPv4 Address:", font=("Arial", 11))
    ip_label.pack(side=tk.LEFT, padx=(0, 10))

    ip_display = ttk.Entry(ip_frame, font=("Arial", 10), state="readonly")
    ip_display.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # Output Frames
    output_frame = ttk.Frame(main_container)
    output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    # Ping Output
    ping_frame = ttk.LabelFrame(output_frame, text="Ping Your Website ", padding=5)
    ping_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    ping_output = scrolledtext.ScrolledText(ping_frame, height=8, font=("Consolas", 10))
    ping_output.pack(fill=tk.BOTH, expand=True)

    # Traceroute Output
    traceroute_frame = ttk.LabelFrame(output_frame, text="Traceroute Your Website ", padding=5)
    traceroute_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    traceroute_output = scrolledtext.ScrolledText(traceroute_frame, height=8, font=("Consolas", 10))
    traceroute_output.pack(fill=tk.BOTH, expand=True)

    # DNS Output
    dns_frame = ttk.LabelFrame(output_frame, text="DNS Server Details ", padding=5)
    dns_frame.pack(fill=tk.BOTH, expand=True)

    dns_output = scrolledtext.ScrolledText(dns_frame, height=8, font=("Consolas", 10))
    dns_output.pack(fill=tk.BOTH, expand=True)

    # Create progress frame (initially hidden)
    progress_frame = ttk.Frame(main_container)
    progress_frame.pack(fill=tk.X, pady=5)
    progress_frame.pack_forget()  # Hide initially
    
    # Progress Bar
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(
        progress_frame,
        variable=progress_var,
        maximum=100,
        mode='determinate'
    )
    progress_bar.pack(fill=tk.X, pady=5)
    
    # Progress Label
    progress_label = ttk.Label(progress_frame, text="Analysis in progress...")
    progress_label.pack(pady=(0, 5))

    # Status Label
    status_label = ttk.Label(main_container, text="", font=("Arial", 10, "bold"))
    status_label.pack(pady=(0, 10))

    # Run Button
    run_button = ttk.Button(
        main_container,
        text="Run Analysis",
        command=lambda: run_analysis(
            url_entry.get(),
            ip_display,
            ping_output,
            traceroute_output,
            dns_output,
            progress_frame,
            progress_bar,
            progress_label,
            progress_var,
            status_label,
            run_button
        )
    )
    run_button.pack(pady=(0, 10))

    return main_container

def get_ip_address(url):
    """Get IPv4 address for the given URL."""
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    
    url = url.split('/')[0]
    
    try:
        # Force IPv4 resolution
        ip_address = socket.gethostbyname_ex(url)[2][0]
        return ip_address
    except socket.gaierror:
        return "Could not resolve hostname"

def run_analysis(url, ip_display, ping_output, traceroute_output, dns_output, progress_frame, progress_bar, progress_label, progress_var, status_label, run_button):
    """Run network analysis for the given URL."""
    if not url or url == "e.g., www.google.com":
        status_label.config(text="Please enter a valid website URL")
        return

    # Clear previous results
    ip_display.config(state="normal")
    ip_display.delete(0, tk.END)
    ip_display.config(state="readonly")
    ping_output.delete(1.0, tk.END)
    traceroute_output.delete(1.0, tk.END)
    dns_output.delete(1.0, tk.END)

    # Reset and show progress bar
    progress_var.set(0)
    progress_frame.pack(fill=tk.X, pady=5)
    progress_label.config(text="Initializing analysis...")

    # Disable run button
    run_button.config(state="disabled")
    status_label.config(text="Analysis in progress...")

    def run_commands():
        try:
            # Update progress to 10% - starting analysis
            progress_var.set(10)
            progress_label.config(text=f"Resolving IPv4 address for {url}...")
            
            # Get and display IP address
            ip_address = get_ip_address(url)
            ip_display.config(state="normal")
            ip_display.delete(0, tk.END)
            ip_display.insert(0, ip_address)
            ip_display.config(state="readonly")
            
            # Update progress to 30% - IP resolved
            progress_var.set(30)
            progress_label.config(text="Running ping test...")

            # Determine commands based on OS
            system = platform.system().lower()
            
            # Run ping (IPv4 only)
            if system == 'windows':
                ping_cmd = f"ping -4 -n 4 {url}"
            else:
                ping_cmd = f"ping -4 -c 4 {url}"
            ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, shell=True)
            ping_output.insert(tk.END, ping_result.stdout or ping_result.stderr)
            
            # Update progress to 50% - ping complete
            progress_var.set(50)
            progress_label.config(text="Running traceroute...")

            # Run traceroute (IPv4 only)
            if system == 'windows':
                traceroute_cmd = f"tracert -d -4 {url}"
            else:
                traceroute_cmd = f"traceroute -4 -n {url}"
            traceroute_result = subprocess.run(traceroute_cmd, capture_output=True, text=True, shell=True)
            traceroute_output.insert(tk.END, traceroute_result.stdout or traceroute_result.stderr)
            
            # Update progress to 70% - traceroute complete
            progress_var.set(70)
            progress_label.config(text="Getting DNS information...")

            # Run nslookup (IPv4 only)
            nslookup_cmd = f"nslookup -type=A {url}"   #nslookup -type=A
            nslookup_result = subprocess.run(nslookup_cmd, capture_output=True, text=True, shell=True)
            dns_output.insert(tk.END, nslookup_result.stdout or nslookup_result.stderr)
            
            # Update progress to 100% - all tests complete
            progress_var.set(100)
            progress_label.config(text="Analysis completed successfully!")
            status_label.config(text="Analysis completed successfully!")

        except Exception as e:
            status_label.config(text=f"Error during analysis: {str(e)}")
            progress_label.config(text=f"Error: {str(e)}")
        finally:
            # Re-enable run button
            run_button.config(state="normal")
            
            # Hide progress bar after a short delay
            def hide_progress():
                progress_frame.after(1000, progress_frame.pack_forget)
            
            progress_frame.after(1000, hide_progress)

    # Run commands in a separate thread
    threading.Thread(target=run_commands, daemon=True).start()
