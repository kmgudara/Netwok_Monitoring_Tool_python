import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as messagebox
import sys
import os

def check_dependencies():
    missing_deps = []
    try:
        import psutil
    except ImportError:
        missing_deps.append("psutil")
    try:
        import pandas
    except ImportError:
        missing_deps.append("pandas")
    try:
        import matplotlib
    except ImportError:
        missing_deps.append("matplotlib")
    try:
        import scapy
    except ImportError:
        missing_deps.append("scapy")
    try:
        import nmap
    except ImportError:
        missing_deps.append("python-nmap")
    
    if missing_deps:
        messagebox.showerror("Missing Dependencies", 
            f"The following required packages are missing:\n{', '.join(missing_deps)}\n\n"
            "Please install them using pip:\n"
            "pip install " + " ".join(missing_deps))
        return False
    return True

def check_files():
    missing_files = []
    if not os.path.exists("oui.csv"):
        missing_files.append("oui.csv")
    if not os.path.exists("module/mac_vendors.csv"):
        missing_files.append("module/mac_vendors.csv")
    
    if missing_files:
        messagebox.showerror("Missing Files", 
            f"The following required files are missing:\n{', '.join(missing_files)}")
        return False
    return True

# Only import module pages after dependency checks
from module.page01 import create_page01
from module.page02 import create_page02
from module.page03 import create_page03
from module.page04 import create_page04
from module.page05 import create_page05
from module.page06 import create_page06
from module.page07 import create_page07

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor")
        self.root.geometry("1200x800")
        
        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create header frame with a distinct style
        self.header_frame = ttk.Frame(self.main_container)
        self.header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create a style for the header
        style = ttk.Style()
        style.configure('Header.TFrame', background='#f0f0f0')
        style.configure('Header.TButton', padding=10, font=('Helvetica', 10))
        style.configure('Active.TButton', background='#007bff', foreground='white')
        
        # Apply header style
        self.header_frame.configure(style='Header.TFrame')
        
        # Create navigation buttons
        self.nav_buttons = []
        self.pages = [
            ("Network Info", create_page01),
            ("Network Stats", create_page02),
            ("Network Mirror", create_page03),
            ("ARP Scanner", create_page04),
            ("Network Scanner", create_page05),
            ("Port Scanner", create_page06),
            ("Traceroute", create_page07)
        ]
        
        print("Initializing navigation buttons...")
        # Create navigation buttons with improved styling
        for i, (title, _) in enumerate(self.pages):
            btn = ttk.Button(
                self.header_frame,
                text=title,
                command=self.create_page_command(i),
                style='Header.TButton'
            )
            btn.pack(side=tk.LEFT, padx=2)
            self.nav_buttons.append(btn)
            
            # Add separator between buttons (except for the last one)
            if i < len(self.pages) - 1:
                ttk.Separator(self.header_frame, orient='vertical').pack(side=tk.LEFT, padx=5, fill='y')
        
        # Create content frame with padding
        self.content_frame = ttk.Frame(self.main_container)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Initialize current page
        self.current_page = None
        self.current_page_index = 0
        
        print("Showing default page (index 0)...")
        # Show first page by default
        self.show_page(0)
    
    def create_page_command(self, index):
        """Create a command function for the page button."""
        def command():
            self.show_page(index)
        return command
    
    def show_page(self, index):
        print(f"Attempting to show page {index} ({self.pages[index][0]})")
        try:
            # Clear current page
            if self.current_page:
                print("Clearing current page...")
                self.current_page.destroy()
            
            # Update button states and styles
            for i, btn in enumerate(self.nav_buttons):
                if i == index:
                    btn.state(['disabled'])
                    btn.configure(style='Active.TButton')
                else:
                    btn.state(['!disabled'])
                    btn.configure(style='Header.TButton')
            
            # Create and show new page
            _, page_creator = self.pages[index]
            print(f"Creating new page using {page_creator.__name__}...")
            self.current_page = page_creator(self.content_frame)
            self.current_page_index = index
            print(f"Page {index} created successfully")
        except Exception as e:
            print(f"Error showing page {index}: {e}")
            messagebox.showerror("Error", f"Failed to load page: {str(e)}")

def main():
    print("Starting Network Monitor application...")
    
    # Check dependencies and files before starting
    if not check_dependencies() or not check_files():
        sys.exit(1)
    
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
