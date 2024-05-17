import requests
import json
import os
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import threading
import webbrowser
import time  # Import the time module

# URL of the JSON file
url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

# Files to save data
previous_data_file = 'previous_vulnerabilities.json'
selected_vendors_file = 'selected_vendors.json'

# Function to fetch the JSON data from the URL
def fetch_json_data(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        messagebox.showerror("Error", f"Failed to fetch data: {response.status_code}")
        return None

# Function to compare current data with previous data
def compare_data(current_data, previous_data):
    if not previous_data:
        return current_data
    new_vulnerabilities = []
    current_ids = {item['cveID'] for item in current_data}
    previous_ids = {item['cveID'] for item in previous_data}
    new_ids = current_ids - previous_ids
    for item in current_data:
        if item['cveID'] in new_ids:
            new_vulnerabilities.append(item)
    return new_vulnerabilities

# Function to save data to a file
def save_data_to_file(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file)

# Function to load data from a file
def load_data_from_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    else:
        return None

# Function to get a list of unique vendors
def get_unique_vendors(vulnerabilities):
    return sorted(set(item['vendorProject'] for item in vulnerabilities))

# Function to filter and sort vulnerabilities by vendor
def filter_vulnerabilities_by_vendors(vulnerabilities, selected_vendors):
    filtered_vulnerabilities = [item for item in vulnerabilities if item['vendorProject'] in selected_vendors]
    return sorted(filtered_vulnerabilities, key=lambda x: datetime.strptime(x['dateAdded'], '%Y-%m-%d'), reverse=True)

# Function to display vulnerabilities in the GUI
def display_vulnerabilities(vulnerabilities, new_vulnerabilities):
    result_text.delete('1.0', tk.END)
    for vulnerability in vulnerabilities:
        is_new = vulnerability in new_vulnerabilities
        tag = "new" if is_new else "normal"
        result_text.insert(tk.END, f"CVE ID: {vulnerability['cveID']}\n", tag)
        result_text.insert(tk.END, f"Product: {vulnerability['product']}\n")
        result_text.insert(tk.END, f"Vulnerability Name: {vulnerability['vulnerabilityName']}\n")
        result_text.insert(tk.END, f"Date Added: {vulnerability['dateAdded']}\n")
        result_text.insert(tk.END, f"Short Description: {vulnerability['shortDescription']}\n")
        
        more_details_label = tk.Label(result_text, text="Click for more details", fg="blue", cursor="hand2")
        more_details_label.pack()
        more_details_label.bind("<Button-1>", lambda e, v=vulnerability: show_details(v))
        
        result_text.window_create(tk.END, window=more_details_label)
        result_text.insert(tk.END, "\n")

        cvss_link = f"https://nvd.nist.gov/vuln/detail/{vulnerability['cveID']}"
        cvss_label = tk.Label(result_text, text="CVSS Score", fg="blue", cursor="hand2")
        cvss_label.pack()
        cvss_label.bind("<Button-1>", lambda e, link=cvss_link: webbrowser.open(link))
        
        result_text.window_create(tk.END, window=cvss_label)
        result_text.insert(tk.END, "\n\n")

    result_text.tag_configure("new", background="yellow")
    result_text.tag_configure("normal", background="white")

# Function to handle vendor selection
def on_select(event):
    selected_indices = vendor_listbox.curselection()
    selected_vendors = [vendor_listbox.get(i) for i in selected_indices]
    save_data_to_file(selected_vendors, selected_vendors_file)
    filtered_vulnerabilities = filter_vulnerabilities_by_vendors(current_data['vulnerabilities'], selected_vendors)
    new_vulnerabilities = compare_data(current_data['vulnerabilities'], previous_data)
    display_vulnerabilities(filtered_vulnerabilities, new_vulnerabilities)
    display_selected_vendors(selected_vendors)

# Function to refresh data automatically
def auto_refresh():
    while True:
        fetch_and_update_data()
        time.sleep(3600)  # Refresh every hour

# Function to fetch and update data
def fetch_and_update_data():
    global current_data, previous_data
    new_data = fetch_json_data(url)
    if new_data:
        current_data = new_data
        save_data_to_file(current_data['vulnerabilities'], previous_data_file)
        vendors = get_unique_vendors(current_data['vulnerabilities'])
        vendor_listbox.delete(0, tk.END)
        for vendor in vendors:
            vendor_listbox.insert(tk.END, vendor)
        load_selected_vendors()

# Function to show detailed information in a new window
def show_details(vulnerability):
    detail_window = tk.Toplevel(root)
    detail_window.title(f"Details for {vulnerability['cveID']}")
    
    tk.Label(detail_window, text=f"CVE ID: {vulnerability['cveID']}").pack(pady=5)
    tk.Label(detail_window, text=f"Vendor: {vulnerability['vendorProject']}").pack(pady=5)
    tk.Label(detail_window, text=f"Product: {vulnerability['product']}").pack(pady=5)
    tk.Label(detail_window, text=f"Vulnerability Name: {vulnerability['vulnerabilityName']}").pack(pady=5)
    tk.Label(detail_window, text=f"Date Added: {vulnerability['dateAdded']}").pack(pady=5)
    tk.Label(detail_window, text=f"Short Description: {vulnerability['shortDescription']}").pack(pady=5)
    tk.Label(detail_window, text=f"Required Action: {vulnerability['requiredAction']}").pack(pady=5)
    tk.Label(detail_window, text=f"Due Date: {vulnerability['dueDate']}").pack(pady=5)
    tk.Label(detail_window, text=f"Notes: {vulnerability['notes']}").pack(pady=5)

# Function to load selected vendors from a file
def load_selected_vendors():
    selected_vendors = load_data_from_file(selected_vendors_file)
    if selected_vendors:
        for vendor in selected_vendors:
            index = vendor_listbox.get(0, tk.END).index(vendor)
            vendor_listbox.select_set(index)
        filtered_vulnerabilities = filter_vulnerabilities_by_vendors(current_data['vulnerabilities'], selected_vendors)
        new_vulnerabilities = compare_data(current_data['vulnerabilities'], previous_data)
        display_vulnerabilities(filtered_vulnerabilities, new_vulnerabilities)
        display_selected_vendors(selected_vendors)

# Function to display selected vendors
def display_selected_vendors(selected_vendors):
    selected_vendors_text.delete('1.0', tk.END)
    selected_vendors_text.insert(tk.END, "Selected Vendors:\n")
    for vendor in selected_vendors:
        selected_vendors_text.insert(tk.END, f"{vendor}\n")

# Function to filter the vendor list based on the search query
def filter_vendors(*args):
    search_query = search_var.get().lower()
    vendor_listbox.delete(0, tk.END)
    for vendor in vendors:
        if search_query in vendor.lower():
            vendor_listbox.insert(tk.END, vendor)

# Fetch current data
current_data = fetch_json_data(url)
if not current_data:
    exit()

# Load previous data
previous_data = load_data_from_file(previous_data_file)

# Compare data to find new vulnerabilities
new_vulnerabilities = compare_data(current_data['vulnerabilities'], previous_data)

# Save current data for future comparisons
save_data_to_file(current_data['vulnerabilities'], previous_data_file)

# Get unique vendors from the vulnerabilities
vendors = get_unique_vendors(current_data['vulnerabilities'])

# Create the main window
root = tk.Tk()
root.title("Vulnerability Scanner")

# Create frames for layout
left_frame = tk.Frame(root)
left_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

middle_frame = tk.Frame(root)
middle_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

right_frame = tk.Frame(root)
right_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)

# Create and pack the vendor search box
search_var = tk.StringVar()
search_var.trace("w", filter_vendors)
search_entry = tk.Entry(left_frame, textvariable=search_var, width=30)
search_entry.pack(pady=5)

# Create and pack the vendor listbox in the left frame
vendor_label = tk.Label(left_frame, text="Select Vendors:")
vendor_label.pack(pady=5)
vendor_listbox = tk.Listbox(left_frame, selectmode=tk.MULTIPLE, exportselection=False)
for vendor in vendors:
    vendor_listbox.insert(tk.END, vendor)
vendor_listbox.pack(pady=5, fill=tk.Y)
vendor_listbox.bind("<<ListboxSelect>>", on_select)

# Create and pack the text widget to display selected vendors in the middle frame
selected_vendors_text = tk.Text(middle_frame, wrap=tk.WORD, width=40, height=20)
selected_vendors_text.pack(pady=10, fill=tk.Y)

# Create and pack the text widget to display vulnerabilities in the right frame
result_text = tk.Text(right_frame, wrap=tk.WORD, width=80, height=20)
result_text.pack(pady=10, fill=tk.BOTH, expand=True)

# Load previously selected vendors
load_selected_vendors()

# Start the automatic refresh thread
threading.Thread(target=auto_refresh, daemon=True).start()

# Start the GUI main loop
root.mainloop()
