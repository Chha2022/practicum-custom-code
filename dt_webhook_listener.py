import http.server
import json
import os
import threading
import requests  # Import requests to send data to Splunk
from project_sbom_analyzer import fetch_vendor_contact
from email_notifier import buffer_event_and_send, flush_buffer

# Webhook Listener Configuration
HOST = '127.0.0.1'
PORT = 8888
RAW_OUTPUT_FILE = "raw_events.json"  # File to save raw JSON data
FORMATTED_OUTPUT_FILE = "formatted_events.txt"  # File to save formatted, readable data with vulnerabilities

# Splunk HEC Configuration
SPLUNK_HEC_URL = "http://127.0.0.1:8077/services/collector"
SPLUNK_AUTH_TOKEN = "e493377a-7cb6-4616-8e78-aaa9e75db4df"

# Dictionary to store detailed vulnerability information by component UUID
vulnerability_details = {}
dependency_notifications = []  # Added definition for the missing variable
all_vulnerabilities = []  # List to accumulate all vulnerability notifications
email_delay_timer = None
email_delay_seconds = 20  # Delay in seconds to batch notifications

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

def send_to_splunk():
    """Sends all accumulated vulnerability notifications to Splunk using HEC."""
    if not all_vulnerabilities:
        print("No vulnerabilities to send to Splunk.")
        return

    # Prepare the event data for Splunk with total count
    splunk_event = {
        "event": {
            "total_vulnerabilities": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities
        },
        "sourcetype": "_json",
        "index": "main",
        "source": "http:SBOM_Alert_Notifications"
    }

    try:
        response = requests.post(
            SPLUNK_HEC_URL,
            headers={
                "Authorization": f"Splunk {SPLUNK_AUTH_TOKEN}",
                "Content-Type": "application/json"
            },
            json=splunk_event,
            verify=False
        )
        if response.status_code == 200:
            print("Vulnerability data successfully sent to Splunk.")
        else:
            print(f"Failed to send data to Splunk: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending data to Splunk: {e}")

    # Clear the list after sending
    all_vulnerabilities.clear()

def send_notifications():
    """Sends both Splunk and email notifications."""
    send_to_splunk()  # Send accumulated vulnerabilities to Splunk
    flush_buffer()  # Send email notifications

def delay_send_notifications():
    """Function to send the accumulated notifications (Splunk and email) after a delay."""
    global email_delay_timer
    if email_delay_timer:
        email_delay_timer.cancel()  # Cancel any existing timer
    email_delay_timer = threading.Timer(email_delay_seconds, send_notifications)
    email_delay_timer.start()

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global email_delay_timer

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
            subject = notification.get("subject", {})

            if group == "NEW_VULNERABILITY":
                # Store detailed vulnerability information
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
                # Collect dependency notifications
                dependency_notifications.append(notification)
                subject = notification.get("subject", {})
                project = subject.get("project", {})
                component = subject.get("component", {})
                vulnerabilities = subject.get("vulnerabilities", [])

                project_name = project.get("name", "Unknown Project")
                project_id = project.get("uuid", "Unknown ID")
                component_name = component.get("name", "Unknown Component")
                component_version = component.get("version", "Unknown Version")

                # Fetch vendor contact information
                try:
                    vendor_contact = fetch_vendor_contact(project_id)
                    contact_email = vendor_contact['email'] if vendor_contact else None
                    vendor_first_name = vendor_contact['first_name'] if vendor_contact else "Vendor"
                    print(f"Contact Email: {contact_email}, Vendor First Name: {vendor_first_name}")
                except Exception as e:
                    print(f"Error fetching vendor contact for project {project_id}: {e}")
                    contact_email = None
                    vendor_first_name = "Vendor"

                # Enrich the vulnerabilities with additional details if available
                enriched_vulnerabilities = []
                for vuln in vulnerabilities:
                    enriched_vulnerabilities.append({
                        "vulnId": vuln.get("vulnId", "Unknown ID"),
                        "severity": vuln.get("severity", "Unknown Severity"),
                        "description": vuln.get("description", "No description")[:140]
                    })

                # Prepare event data for the email
                event_data = {
                    "project_name": project_name,
                    "component_name": component_name,
                    "component_version": component_version,
                    "vulnerabilities": enriched_vulnerabilities,
                    "contact_email": contact_email,
                    "vendor_first_name": vendor_first_name
                }

                # Buffer the event without enforcing a fixed batch size
                buffer_event_and_send(contact_email, vendor_first_name, event_data)

                # Accumulate vulnerability notifications for Splunk
                all_vulnerabilities.append(event_data)

                # Trigger the delayed send for both Splunk and email
                delay_send_notifications()

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
    if email_delay_timer:
        email_delay_timer.cancel()  # Cancel the timer on exit
    send_notifications()  # Send any remaining notifications before shutting down
    print("Server stopped.")
