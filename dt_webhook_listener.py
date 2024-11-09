import http.server
import json
import os

# Webhook Listener Configuration
HOST = '127.0.0.1'
PORT = 8888
RAW_OUTPUT_FILE = "raw_events.json"  # File to save raw JSON data
FORMATTED_OUTPUT_FILE = "formatted_events.txt"  # File to save formatted, readable data with vulnerabilities

# Function to check for existing files and prompt the user
def handle_existing_files():
    if os.path.exists(RAW_OUTPUT_FILE) or os.path.exists(FORMATTED_OUTPUT_FILE):
        # Ask the user if they want to delete the existing files
        response = input("Do you want to delete the existing files? (y/n): ").strip().lower()
        if response == 'y':
            # Delete the files if they exist
            if os.path.exists(RAW_OUTPUT_FILE):
                os.remove(RAW_OUTPUT_FILE)
            if os.path.exists(FORMATTED_OUTPUT_FILE):
                os.remove(FORMATTED_OUTPUT_FILE)
            print("Existing files deleted.")
        else:
            print("Files will be opened in append mode.")

# Handle the files based on user input only if the files exist
handle_existing_files()

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the raw byte data from the incoming request
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Attempt to decode the byte data to a UTF-8 string
        try:
            data = post_data.decode('utf-8', errors='replace')  # Replace invalid bytes
        except UnicodeDecodeError:
            print("Failed to decode byte data with UTF-8")
            self.send_response(400)  # Bad Request
            self.end_headers()
            self.wfile.write(b'Invalid character encoding in request')
            return

        try:
            # Parse the JSON data
            json_data = json.loads(data)

            # Save the raw JSON data to a file
            with open(RAW_OUTPUT_FILE, "a", encoding="utf-8") as raw_file:
                raw_file.write(json.dumps(json_data) + "\n")  # Write each event as a new line

            # Check if the notification "group" is "NEW_VULNERABLE_DEPENDENCY"
            notification = json_data.get("notification", {})
            group = notification.get("group")

            if group == "NEW_VULNERABLE_DEPENDENCY":
                # Extract and format the project details
                subject = notification.get("subject", {})
                project = subject.get("project", {})
                component = subject.get("component", {})
                vulnerabilities = subject.get("vulnerabilities", [])

                project_name = project.get("name", "Unknown Project")
                project_id = project.get("uuid", "Unknown ID")
                component_name = component.get("name", "Unknown Component")
                component_version = component.get("version", "Unknown Version")

                # Format the vulnerabilities for better readability
                formatted_vulnerabilities = []
                for vuln in vulnerabilities:
                    vuln_id = vuln.get("vulnId", "Unknown Vulnerability ID")
                    severity = vuln.get("severity", "Unknown Severity")
                    description = vuln.get("description", "No Description Available")
                    cvssv3_score = vuln.get("cvssv3", "N/A")

                    formatted_vulnerabilities.append(
                        f"  - ID: {vuln_id} | Severity: {severity}\n"
                        f"    CVSSv3 Score: {cvssv3_score}\n"
                        f"    Description: {description}"
                    )

                # Create a formatted string with project and vulnerability details
                formatted_data = (
                    f"Project Name: {project_name}\n"
                    f"Project ID: {project_id}\n"
                    f"Component: {component_name} (Version: {component_version})\n"
                    f"Vulnerabilities:\n" + "\n".join(formatted_vulnerabilities) + "\n---\n"
                )

                # Save the formatted project and vulnerability details to a file
                with open(FORMATTED_OUTPUT_FILE, "a", encoding="utf-8") as formatted_file:
                    formatted_file.write(formatted_data)  # Write each formatted entry separated by a line

                print(f"Saved project: {project_name} with ID: {project_id} and vulnerabilities listed")

        except json.JSONDecodeError:
            print("Failed to decode JSON")  # Handle invalid JSON data

        # Respond with a 200 OK status
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Webhook received successfully')

# Create and run the HTTP server
httpd = http.server.HTTPServer((HOST, PORT), WebhookHandler)
print(f"HTTP Server running on http://{HOST}:{PORT}")
httpd.serve_forever()
