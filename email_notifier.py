import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Gmail SMTP configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
GMAIL_USER = "arun.cs6727@gmail.com"  # Replace with your Gmail address
GMAIL_PASSWORD = "ckhrjpgevldhsxpo"  # Replace with your Gmail app password

# Configurable event batch size
EVENT_BATCH_SIZE = 20  # Default to 20

# Store alerts to be sent
event_buffer = []

def send_email_to_vendor(contact_email, events):
    """Sends an email to the vendor with a bundled list of events."""
    if not contact_email or not events:
        print("No email or events to send.")
        return

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = GMAIL_USER
    msg['To'] = contact_email
    msg['Subject'] = "Vulnerability Alerts for Your Project"

    # Format the events in the email body
    body = "Dear Vendor,\n\nYou have the following new vulnerability alerts for your project(s):\n\n"
    body += "<table border='1' style='border-collapse: collapse; width: 100%;'>"
    body += "<tr><th>Project</th><th>Component</th><th>Version</th><th>Vulnerability</th></tr>"

    # Create a JSON object for the attachment
    attachment_data = []

    for event in events:
        # Limit the description to 140 characters
        formatted_vulnerabilities = [
            f"ID: {vuln['vulnId']} | Severity: {vuln['severity']} | Description: {vuln['description'][:140]}"
            for vuln in event['vulnerabilities']
        ]

        # Add table row for each event
        body += f"<tr><td>{event['project_name']}</td>"
        body += f"<td>{event['component_name']}</td>"
        body += f"<td>{event['component_version']}</td>"
        body += "<td><ul>"
        for vuln in formatted_vulnerabilities:
            body += f"<li>{vuln}</li>"
        body += "</ul></td></tr>"

        # Add the event to the JSON attachment data
        attachment_data.append(event)

    body += "</table>"
    body += "\n\nPlease address these vulnerabilities as soon as possible.\n\nRegards,\nSecurity Team"

    # Attach the body to the email
    msg.attach(MIMEText(body, 'html'))

    # Create the JSON attachment
    json_attachment = json.dumps(attachment_data, indent=4)
    attachment = MIMEBase('application', 'octet-stream')
    attachment.set_payload(json_attachment.encode('utf-8'))
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', 'attachment', filename="vulnerability_alerts.json")
    msg.attach(attachment)

    try:
        # Connect to the Gmail SMTP server and send the email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Start TLS encryption
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Email sent to {contact_email} with {len(events)} events.")
    except Exception as e:
        print(f"Failed to send email: {e}")

def buffer_event_and_send(contact_email, event_data):
    """Buffers events and sends them in batches."""
    global event_buffer
    event_buffer.append(event_data)

    if len(event_buffer) >= EVENT_BATCH_SIZE:  # Check if we have enough events in the buffer
        send_email_to_vendor(contact_email, event_buffer)
        event_buffer = []  # Clear the buffer after sending

def flush_buffer():
    """Sends any remaining events in the buffer."""
    if event_buffer:
        # Use the contact email from the first event in the buffer
        contact_email = event_buffer[0]['contact_email']
        send_email_to_vendor(contact_email, event_buffer)
        event_buffer.clear()

# Example code to send a test email when running this script directly
if __name__ == "__main__":
    # Example event data for testing
    default_events = [
        {
            "project_name": "Default Project",
            "component_name": "Default Component",
            "component_version": "1.0.0",
            "vulnerabilities": [
                {"vulnId": "CVE-2024-12345", "severity": "HIGH", "description": "This is an example vulnerability description that will be truncated to 140 characters."}
            ],
            "contact_email": "arun.cs6727@gmail.com"  # Replace with your real email address
        }
    ]

    # Buffer the default event and send
    for event in default_events:
        buffer_event_and_send(event["contact_email"], event)

    # Flush any remaining events to ensure the email is sent
    flush_buffer()
