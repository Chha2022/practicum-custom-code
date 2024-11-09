import http.server
import json
import os
from project_sbom_analyzer import fetch_vendor_contact
from email_notifier import buffer_event_and_send, flush_buffer  # Import the functions from email_notifier

# Webhook Listener Configuration
HOST = '127.0.0.1'
PORT = 8888
RAW_OUTPUT_FILE = "raw_events.json"  # File to save raw JSON data
FORMATTED_OUTPUT_FILE = "formatted_events.txt"  # File to save formatted, readable data with vulnerabilities

# Function to check for existing files and prompt the user
def handle_existing_files():
    if os.path.exists(RAW_OUTPUT_FILE) or os.path.exists(FORMATTED_OUTPUT_FILE):
        response = input("Do you want to delete the existing files? (y/n): ").strip().lower()
        if response == 'y':
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
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = post_data.decode('utf-8', errors='replace')  # Replace invalid bytes
        except UnicodeDecodeError:
            print("Failed to decode byte data with UTF-8")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Invalid character encoding in request')
            return

        try:
            json_data = json.loads(data)
            with open(RAW_OUTPUT_FILE, "a", encoding="utf-8") as raw_file:
                raw_file.write(json.dumps(json_data) + "\n")

            notification = json_data.get("notification", {})
            group = notification.get("group")

            if group == "NEW_VULNERABLE_DEPENDENCY":
                subject = notification.get("subject", {})
                project = subject.get("project", {})
                component = subject.get("component", {})
                vulnerabilities = subject.get("vulnerabilities", [])

                project_name = project.get("name", "Unknown Project")
                project_id = project.get("uuid", "Unknown ID")
                component_name = component.get("name", "Unknown Component")
                component_version = component.get("version", "Unknown Version")

                vendor_contact = fetch_vendor_contact(project_id)
                contact_email = vendor_contact['email'] if vendor_contact else None

                formatted_vulnerabilities = [
                    f"ID: {vuln.get('vulnId')} | Severity: {vuln.get('severity')} | Description: {vuln.get('description')}"
                    for vuln in vulnerabilities
                ]

                # Prepare event data for the email
                event_data = {
                    "project_name": project_name,
                    "project_id": project_id,
                    "component_name": component_name,
                    "component_version": component_version,
                    "vulnerabilities": formatted_vulnerabilities,
                    "contact_email": contact_email
                }

                # Buffer the event and send in batches of 20
                buffer_event_and_send(contact_email, event_data)

                formatted_data = (
                    f"Project Name: {project_name}\n"
                    f"Project ID: {project_id}\n"
                    f"Component: {component_name} (Version: {component_version})\n"
                    f"Vendor Contact: {vendor_contact}\n"
                    f"Vulnerabilities:\n" + "\n".join(formatted_vulnerabilities) + "\n---\n"
                )

                with open(FORMATTED_OUTPUT_FILE, "a", encoding="utf-8") as formatted_file:
                    formatted_file.write(formatted_data)
                print(f"Saved project: {project_name} with ID: {project_id} and vulnerabilities listed")

        except json.JSONDecodeError:
            print("Failed to decode JSON")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Webhook received successfully')

# Create and run the HTTP server
httpd = http.server.HTTPServer((HOST, PORT), WebhookHandler)
print(f"HTTP Server running on http://{HOST}:{PORT}")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    flush_buffer()  # Send any remaining events before shutting down
    print("Server stopped and buffer flushed.")
