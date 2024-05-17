import requests
import json
import os
import tkinter as tk
from tkinter import ttk, messagebox

# URL of the JSON file
url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

# File to save the previous data
previous_data_file = 'previous_vulnerabilities.json'

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

# Function to save the current data to a file
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

# Function to filter vulnerabilities by vendor
def filter_vulnerabilities_by_vendor(vulnerabilities, vendor):
    return [item for item in vulnerabilities if item['vendorProject'] == vendor]

# Function to display vulnerabilities in the GUI
def display_vulnerabilities(vulnerabilities):
    result_text.delete('1.0', tk.END)
    for vulnerability in vulnerabilities:
        result_text.insert(tk.END, f"CVE ID: {vulnerability['cveID']}\n")
        result_text.insert(tk.END, f"Product: {vulnerability['product']}\n")
        result_text.insert(tk.END, f"Vulnerability Name: {vulnerability['vulnerabilityName']}\n")
        result_text.insert(tk.END, f"Date Added: {vulnerability['dateAdded']}\n")
        result_text.insert(tk.END, f"Short Description: {vulnerability['shortDescription']}\n")
        result_text.insert(tk.END, "\n")

# Function to handle vendor selection
def on_select(event):
    selected_vendor = vendor_combobox.get()
    filtered_vulnerabilities = filter_vulnerabilities_by_vendor(current_data['vulnerabilities'], selected_vendor)
    display_vulnerabilities(filtered_vulnerabilities)

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

# Create and pack the vendor combobox
vendor_label = tk.Label(root, text="Select Vendor:")
vendor_label.pack(pady=5)
vendor_combobox = ttk.Combobox(root, values=vendors)
vendor_combobox.pack(pady=5)
vendor_combobox.bind("<<ComboboxSelected>>", on_select)

# Create and pack the text widget to display vulnerabilities
result_text = tk.Text(root, wrap=tk.WORD, width=80, height=20)
result_text.pack(pady=10)

# Start the GUI main loop
root.mainloop()
