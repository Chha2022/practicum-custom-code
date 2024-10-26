import requests

# Set your API token here
api_token = "odt_sbxd8GFPOKF3QzKGkOZzgCkyfPLnYeHv"

# Base URL of your Dependency-Track server
base_url = "http://localhost:8081/api/v1"

# Set headers for the API requests using X-Api-Key
headers = {
    "X-Api-Key": api_token,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# Function to create a new project (PUT request)
def create_project():
    payload = {
        "name": "Test Project",
        "version": "1.0",
        "description": "A test project",
        "active": True
    }
    
    try:
        response = requests.put(f"{base_url}/project", json=payload, headers=headers)
        if response.status_code == 201 or response.status_code == 200:
            print("Project created successfully!")
            project_data = response.json()
            project_uuid = project_data.get('uuid')
            print(f"Project UUID: {project_uuid}")
            return project_uuid
        else:
            print(f"Failed to create project: {response.status_code}")
            print(f"Error details: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
    return None

# Function to add a custom property to the project (PUT request)
def add_project_property(project_uuid, property_name, property_value, property_type="STRING", description=""):
    property_url = f"{base_url}/project/{project_uuid}/property"
    property_payload = {
        # Removed the "project" field as it's already in the URL
        "groupName": "Supplier Information",  # You can customize the group
        "propertyName": property_name,
        "propertyValue": property_value,
        "propertyType": property_type,
        "description": description
    }

    print(f"Adding property '{property_name}' to project UUID: {project_uuid}")
    try:
        response = requests.put(property_url, json=property_payload, headers=headers)
        if response.status_code == 201:
            print(f"Property '{property_name}' added successfully!")
        else:
            print(f"Failed to add property '{property_name}': {response.status_code}")
            print(f"Error details: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")

# Main script execution
if __name__ == "__main__":
    # Step 1: Create the project
    project_uuid = create_project()
    
    # Step 2: Add custom properties if the project is successfully created
    if project_uuid:
        add_project_property(project_uuid, "Supplier Name", "ABC Supplies Ltd.")
        add_project_property(project_uuid, "Supplier Contact First Name", "John")
        add_project_property(project_uuid, "Supplier Contact Last Name", "Doe")
        add_project_property(project_uuid, "Supplier Contact Email", "john.doe@abc.com")
