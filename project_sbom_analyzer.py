import requests
from tabulate import tabulate

# API base URL and authentication
API_BASE_URL = "http://localhost:8081/api/v1"
API_KEY = "odt_tadX3fUlG56Q7vHZVwjDGyi8Hw0dqLmY"

# Headers for API calls
HEADERS = {
    "X-Api-Key": API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def list_projects():
    """Fetches and returns the list of projects."""
    try:
        response = requests.get(f"{API_BASE_URL}/project", headers=HEADERS)
        if response.status_code == 200:
            return response.json()  # Return project data
        else:
            print(f"Error fetching projects: {response.status_code}")
            print(response.text)
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
            print(response.text)
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

def display_projects_and_risk_scores():
    """Displays projects and their risk scores in a table."""
    projects = list_projects()
    table_data = []

    for project in projects:
        project_uuid = project.get("uuid")
        project_name = project.get("name")
        
        # Fetch and display the risk score
        risk_score = fetch_risk_score(project_uuid)
        table_data.append([project_name, project_uuid, risk_score])

    # Display in tabular format
    headers = ["Project Name", "UUID", "Risk Score"]
    print(tabulate(table_data, headers=headers, tablefmt="pretty"))

def display_critical_projects():
    """Displays only projects with a critical risk score (> 80)."""
    projects = list_projects()
    table_data = []

    for project in projects:
        project_uuid = project.get("uuid")
        project_name = project.get("name")
        
        # Fetch and filter projects based on critical risk score
        risk_score = fetch_risk_score(project_uuid)

        if risk_score and risk_score > 80:  # Only show critical projects
            table_data.append([project_name, project_uuid, risk_score])

    # Display in tabular format
    headers = ["Project Name", "UUID", "Risk Score"]
    print(tabulate(table_data, headers=headers, tablefmt="pretty"))

if __name__ == "__main__":
    print("Step 1: Listing all projects and their risk scores...")
    display_projects_and_risk_scores()

    print("\nStep 2: Listing only critical projects with risk score > 80...")
    display_critical_projects()
