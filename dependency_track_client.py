import requests

class DependencyTrackClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def create_project(self, name="default", version="1.0", description="Test Project Description"):
        if name.lower() == "default":
            name = "Test Project"
            version = "1.0"
        
        url = f"{self.base_url}/v1/project"
        payload = {
            "name": name,
            "version": version,
            "description": description,
            "active": True
        }

        response = requests.put(url, json=payload, headers=self.headers)
        
        if response.status_code in (200, 201):
            project_uuid = response.json().get('uuid')
            print(f"Project '{name}' created successfully with UUID: {project_uuid}")
            return project_uuid
        else:
            print(f"Failed to create project: {response.status_code} - {response.text}")
            return None

    def add_project_property(self, project_uuid, group_name, property_name, property_value, property_type="STRING", description=""):
        url = f"{self.base_url}/v1/project/{project_uuid}/property"
        payload = {
            "groupName": group_name,
            "propertyName": property_name,
            "propertyValue": property_value,
            "propertyType": property_type,
            "description": description
        }

        response = requests.put(url, json=payload, headers=self.headers)

        if response.status_code == 201:
            print(f"Property '{property_name}' added successfully to project {project_uuid}.")
        else:
            print(f"Failed to add property '{property_name}': {response.status_code} - {response.text}")

    def create_project_with_vendor(self, name="default"):
        project_uuid = self.create_project(name=name)

        if project_uuid:
            self.add_project_property(project_uuid, "VendorContact", "VendorFirstName", "John", "STRING", "First name of the vendor contact")
            self.add_project_property(project_uuid, "VendorContact", "VendorLastName", "Doe", "STRING", "Last name of the vendor contact")
            self.add_project_property(project_uuid, "VendorContact", "VendorEmail", "john.doe@example.com", "STRING", "Email of the vendor contact")
        else:
            print("Project creation failed, so no properties were added.")

# Usage Example
if __name__ == "__main__":
    api_key = "odt_tadX3fUlG56Q7vHZVwjDGyi8Hw0dqLmY"  # Replace with actual API key
    base_url = "http://localhost:8081/api"

    client = DependencyTrackClient(base_url, api_key)
    client.create_project_with_vendor("default")
