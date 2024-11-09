import http.server
import json
import os
import time
from project_sbom_analyzer import fetch_vendor_contact
from email_notifier import buffer_event_and_send, flush_buffer

# Webhook Listener Configuration
HOST = '127.0.0.1'
PORT = 8888
RAW_OUTPUT_FILE = "raw_events.json"
FORMATTED_OUTPUT_FILE = "formatted_events.txt"

# Dictionary to store detailed vulnerability information by component UUID
vulnerability_details = {}
dependency_notifications = []

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
            data = post_data.decode('utf-8', errors='replace')
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
            subject = notification.get("subject", {})

            if group == "NEW_VULNERABILITY":
                component = subject.get("component", {})
                vulnerability = subject.get("vulnerability", {})
                component_uuid = component.get("uuid")

                if component_uuid:
                    vulnerability_details[component_uuid] = {
                        "name": component.get("name", "Unknown Component"),
                        "version": component.get("version", "Unknown Version"),
                        "vulnerability": {
                            "id": vulnerability.get("vulnId", "Unknown ID"),
                            "severity": vulnerability.get("severity", "Unknown Severity"),
                            "description": vulnerability.get("description", "No description")
                        }
                    }

            elif group == "NEW_VULNERABLE_DEPENDENCY":
                dependency_notifications.append(notification)
                time.sleep(60)  # Wait to collect related events

                subject = notification.get("subject", {})
                project = subject.get("project", {})
                component = subject.get("component", {})
                vulnerabilities = subject.get("vulnerabilities", [])

                project_name = project.get("name", "Unknown Project")
                project_id = project.get("uuid", "Unknown ID")
                component_uuid = component.get("uuid")
                component_name = component.get("name", "Unknown Component")
                component_version = component.get("version", "Unknown Version")

                vendor_contact = fetch_vendor_contact(project_id)
                contact_email = vendor_contact['email'] if vendor_contact else None
                vendor_first_name = vendor_contact['first_name'] if vendor_contact else "Vendor"

                enriched_vulnerabilities = []
                if component_uuid and component_uuid in vulnerability_details:
                    vuln_info = vulnerability_details[component_uuid]
                    enriched_vulnerabilities.append({
                        "vulnId": vuln_info["vulnerability"]["id"],
                        "severity": vuln_info["vulnerability"]["severity"],
                        "description": vuln_info["vulnerability"]["description"]
                    })
                else:
                    enriched_vulnerabilities = [
                        {"vulnId": vuln.get("vulnId"), "severity": vuln.get("severity"), "description": vuln.get("description")}
                        for vuln in vulnerabilities
                    ]

                event_data = {
                    "project_name": project_name,
                    "component_name": component_name,
                    "component_version": component_version,
                    "vulnerabilities": enriched_vulnerabilities,
                    "contact_email": contact_email,
                    "vendor_first_name": vendor_first_name
                }

                buffer_event_and_send(contact_email, vendor_first_name, event_data)

        except json.JSONDecodeError:
            print("Failed to decode JSON")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Webhook received successfully')

# Run the HTTP server
httpd = http.server.HTTPServer((HOST, PORT), WebhookHandler)
print(f"HTTP Server running on http://{HOST}:{PORT}")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    flush_buffer()
    print("Server stopped and buffer flushed.")
