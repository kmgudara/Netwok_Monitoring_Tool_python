import os
import pandas as pd

# Default MAC database file path
MAC_DB_PATH = os.path.join(os.path.dirname(__file__), 'mac_vendors.csv')

def load_mac_db():
    """
    Load the MAC address database from CSV file.
    If the file doesn't exist, return an empty DataFrame.
    """
    try:
        if os.path.exists(MAC_DB_PATH):
            return pd.read_csv(MAC_DB_PATH)
        else:
            print(f"Warning: MAC database file not found at {MAC_DB_PATH}")
            return pd.DataFrame(columns=["Mac Prefix", "Device Name"])
    except Exception as e:
        print(f"Error loading MAC database: {e}")
        return pd.DataFrame(columns=["Mac Prefix", "Device Name"])

def get_mac_prefix(mac_address):
    """
    Extract the manufacturer prefix from a MAC address.
    Returns the first 6 characters (3 octets) of the MAC address.
    """
    if not mac_address:
        return None
    
    # Remove any separators and convert to uppercase
    mac = mac_address.replace(":", "").replace("-", "").upper()
    
    # Return first 6 characters (3 octets)
    return mac[:6] if len(mac) >= 6 else None

def get_manufacturer_name(mac_prefix, mac_db=None):
    """
    Look up the manufacturer name for a given MAC prefix.
    If mac_db is not provided, load it from the default location.
    """
    if not mac_prefix:
        return "Unknown"
    
    try:
        # Load database if not provided
        if mac_db is None:
            mac_db = load_mac_db()
        
        # Look up the prefix
        result = mac_db[mac_db["Mac Prefix"] == mac_prefix]
        if not result.empty:
            return result.iloc[0]["Device Name"]
    except Exception as e:
        print(f"Error looking up manufacturer: {e}")
    
    return "Unknown"

def update_mac_db(new_entries):
    """
    Update the MAC database with new entries.
    new_entries should be a list of tuples: [(mac_prefix, device_name), ...]
    """
    try:
        # Load existing database
        mac_db = load_mac_db()
        
        # Convert new entries to DataFrame
        new_df = pd.DataFrame(new_entries, columns=["Mac Prefix", "Device Name"])
        
        # Combine existing and new entries, removing duplicates
        updated_db = pd.concat([mac_db, new_df]).drop_duplicates(subset="Mac Prefix", keep="last")
        
        # Save updated database
        updated_db.to_csv(MAC_DB_PATH, index=False)
        return True
    except Exception as e:
        print(f"Error updating MAC database: {e}")
        return False 