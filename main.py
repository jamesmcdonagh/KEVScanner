import requests
import json
import os
from pick import pick

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
        print(f"Failed to fetch data: {response.status_code}")
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

# Function to get a list of unique applications
def get_unique_applications(vulnerabilities):
    applications = set()
    for item in vulnerabilities:
        applications.update(item['product'].split(", "))
    return sorted(applications)

# Function to filter vulnerabilities by application
def filter_vulnerabilities_by_application(vulnerabilities, application):
    return [item for item in vulnerabilities if application in item['product']]

# Main function
def main():
    # Fetch current data
    current_data = fetch_json_data(url)
    if not current_data:
        return

    # Load previous data
    previous_data = load_data_from_file(previous_data_file)

    # Compare data to find new vulnerabilities
    new_vulnerabilities = compare_data(current_data['vulnerabilities'], previous_data)

    # Save current data for future comparisons
    save_data_to_file(current_data['vulnerabilities'], previous_data_file)

    # Get unique applications from the vulnerabilities
    applications = get_unique_applications(current_data['vulnerabilities'])

    # Let the user select an application
    title = 'Please choose an application:'
    application, index = pick(applications, title)

    # Filter vulnerabilities by the selected application
    filtered_vulnerabilities = filter_vulnerabilities_by_application(current_data['vulnerabilities'], application)

    # Display the filtered vulnerabilities
    print(f"Vulnerabilities for {application}:")
    for vulnerability in filtered_vulnerabilities:
        print(f"CVE ID: {vulnerability['cveID']}")
        print(f"Description: {vulnerability['description']}")
        print(f"Product: {vulnerability['product']}")
        print(f"Vendor Project: {vulnerability['vendorProject']}")
        print()

if __name__ == '__main__':
    main()
