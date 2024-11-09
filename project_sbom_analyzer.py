import requests
import random
from tabulate import tabulate

# API base URL and authentication
API_BASE_URL = "http://localhost:8081/api/v1"
API_KEY = "odt_0JEMptaanHhm2zpXpKvgsIBOuuFpgYx4"

# Headers for API calls
HEADERS = {
    "X-Api-Key": API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Random names and domains for generating vendor contacts
COMMON_NAMES = ["Alice", "Bob", "Charlie", "David", "Emma", "Frank", "Grace", "Hannah", "Ivy", "Jack"]
RANDOM_DOMAINS = ["example.com", "testdomain.com", "mockmail.com", "sample.org", "fakemail.net"]

def list_projects():
    """Fetches and returns the list of projects."""
    try:
        response = requests.get(f"{API_BASE_URL}/project", headers=HEADERS)
        if response.status_code == 200:
            return response.json()  # Return project data
        else:
            print(f"Error fetching projects: {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return []

def fetch_risk_score(project_uuid):
    """Fetches the current risk score for a given project UUID."""
    try:
        response = requests.get(f"{API_BASE_URL}/metrics/project/{project_uuid}/current", headers=HEADERS)
        if response.status_code == 200:
            metrics = response.json()
            return metrics.get("inheritedRiskScore")  # Return risk score
        else:
            print(f"Error fetching risk score for project {project_uuid}: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

def fetch_critical_vulnerabilities(project_uuid):
    """Fetches the count of critical vulnerabilities for a given project UUID."""
    try:
        response = requests.get(f"{API_BASE_URL}/vulnerability/project/{project_uuid}", headers=HEADERS)
        if response.status_code == 200:
            vulnerabilities = response.json()
            # Filter critical vulnerabilities
            critical_vulns = [vuln for vuln in vulnerabilities if vuln.get("severity") == "CRITICAL"]
            return len(critical_vulns)  # Return count of critical vulnerabilities
        else:
            print(f"Error fetching vulnerabilities for project {project_uuid}: {response.status_code}")
            return 0
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return 0

def fetch_vendor_contact(project_uuid):
    """Fetches vendor contact properties for a given project UUID."""
    try:
        response = requests.get(f"{API_BASE_URL}/project/{project_uuid}/property", headers=HEADERS)
        if response.status_code == 200:
            properties = response.json()
            first_name = next((prop["propertyValue"] for prop in properties if prop["propertyName"] == "VendorFirstName"), "N/A")
            last_name = next((prop["propertyValue"] for prop in properties if prop["propertyName"] == "VendorLastName"), "N/A")
            email = next((prop["propertyValue"] for prop in properties if prop["propertyName"] == "VendorEmail"), "N/A")
            return {"first_name": first_name, "last_name": last_name, "email": email}
        else:
            print(f"Error fetching vendor contact for project {project_uuid}: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

def delete_existing_property(project_uuid, property_name):
    """Deletes an existing property for a project."""
    try:
        response = requests.get(f"{API_BASE_URL}/project/{project_uuid}/property", headers=HEADERS)
        if response.status_code == 200:
            properties = response.json()
            existing_prop = next((p for p in properties if p["propertyName"] == property_name), None)

            if existing_prop and "uuid" in existing_prop:
                prop_uuid = existing_prop["uuid"]
                delete_url = f"{API_BASE_URL}/project/{project_uuid}/property/{prop_uuid}"
                delete_response = requests.delete(delete_url, headers=HEADERS)
                if delete_response.status_code == 204:
                    print(f"Deleted existing property '{property_name}' for project {project_uuid}.")
                else:
                    print(f"Error deleting property '{property_name}' for project {project_uuid}: {delete_response.status_code}")
            else:
                print(f"No existing property found for '{property_name}' in project {project_uuid}.")
        else:
            print(f"Error fetching properties for deletion for project {project_uuid}: {response.status_code}")
    except requests.RequestException as e:
        print(f"Request error during property deletion: {e}")

def add_or_update_vendor_contact(project_uuid, first_name, last_name, email):
    """Adds or updates vendor contact as project properties."""
    properties = [
        {"propertyName": "VendorFirstName", "propertyValue": first_name},
        {"propertyName": "VendorLastName", "propertyValue": last_name},
        {"propertyName": "VendorEmail", "propertyValue": email}
    ]

    for prop in properties:
        # Delete the existing property to prevent conflicts
        delete_existing_property(project_uuid, prop["propertyName"])

        # Add the new property
        prop_data = {
            "groupName": "VendorContact",
            "propertyName": prop["propertyName"],
            "propertyValue": prop["propertyValue"],
            "propertyType": "STRING"
        }

        try:
            response = requests.post(
                f"{API_BASE_URL}/project/{project_uuid}/property",
                json=prop_data,
                headers=HEADERS
            )

            if response.status_code in [200, 201]:
                print(f"Property '{prop['propertyName']}' successfully updated for project {project_uuid}.")
            else:
                print(f"Error updating property '{prop['propertyName']}' for project {project_uuid}: {response.status_code}")
        except requests.RequestException as e:
            print(f"Request error while updating property '{prop['propertyName']}': {e}")

def generate_random_name():
    """Generates a random common name."""
    return random.choice(COMMON_NAMES)

def generate_random_email(first_name, last_name):
    """Generates a random email address."""
    domain = random.choice(RANDOM_DOMAINS)
    return f"{first_name.lower()}.{last_name.lower()}@{domain}"

def generate_and_add_vendor_contact():
    """Generates and adds vendor contact to critical projects."""
    projects = list_projects()

    for project in projects:
        project_uuid = project.get("uuid")
        project_name = project.get("name")
        risk_score = fetch_risk_score(project_uuid)

        if risk_score and risk_score > 80:  # Consider only critical projects
            first_name = generate_random_name()
            last_name = generate_random_name()
            email = generate_random_email(first_name, last_name)
            add_or_update_vendor_contact(project_uuid, first_name, last_name, email)

def display_critical_projects_with_vulns_and_vendor():
    """Displays critical projects with their risk scores, critical vulnerabilities, and vendor contact."""
    projects = list_projects()
    table_data = []

    for project in projects:
        project_uuid = project.get("uuid")
        project_name = project.get("name")
        risk_score = fetch_risk_score(project_uuid)

        if risk_score and risk_score > 80:  # Only consider critical projects
            critical_vuln_count = fetch_critical_vulnerabilities(project_uuid)
            vendor_contact = fetch_vendor_contact(project_uuid)

            if vendor_contact:
                vendor_info = f"{vendor_contact['first_name']} {vendor_contact['last_name']} ({vendor_contact['email']})"
            else:
                vendor_info = "N/A"

            table_data.append([project_name, project_uuid, risk_score, critical_vuln_count, vendor_info])

    # Display in tabular format
    headers = ["Project Name", "UUID", "Risk Score", "Critical Vulnerabilities", "Vendor Contact"]
    print(tabulate(table_data, headers=headers, tablefmt="pretty"))

if __name__ == "__main__":
    print("Generating and adding vendor contact for critical projects...")
    generate_and_add_vendor_contact()  # Call this function only once

    print("\nListing critical projects with their risk scores, critical vulnerabilities, and vendor contact...")
    display_critical_projects_with_vulns_and_vendor()
