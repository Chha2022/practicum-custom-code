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

def send_email_to_vendor(contact_email, vendor_first_name, events):
    """Sends an email to the vendor with a bundled list of events."""
    if not contact_email or not events:
        print("No email or events to send.")
        return

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = GMAIL_USER
    msg['To'] = contact_email
    msg['Subject'] = "Vulnerability Alerts for Your Project"

    # Format the events in the email body with a styled HTML table
    body = f"""
    <html>
    <head>
        <style>
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
                color: #333;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            tr:hover {{
                background-color: #f1f1f1;
            }}
        </style>
    </head>
    <body>
        <p>Dear {vendor_first_name},</p>
        <p>You have the following new vulnerability alerts for your project(s):</p>
        <table>
            <tr>
                <th>Component</th>
                <th>Version</th>
                <th>Vulnerability</th>
                <th>Severity</th>
            </tr>
    """

    # Create a JSON object for the attachment
    attachment_data = []

    for event in events:
        component = event.get("component_name", "Unknown Component")
        version = event.get("component_version", "Unknown Version")

        for vuln in event.get("vulnerabilities", []):
            if isinstance(vuln, dict):  # Ensure vuln is a dictionary
                vuln_id = vuln.get("vulnId", "Unknown ID")
                severity = vuln.get("severity", "Unknown Severity")

                # Add table row
                body += f"""
                <tr>
                    <td>{component}</td>
                    <td>{version}</td>
                    <td>{vuln_id}</td>
                    <td>{severity}</td>
                </tr>
                """

        # Add the event to the JSON attachment data
        attachment_data.append(event)

    body += """
        </table>
        <p>Please address these vulnerabilities as soon as possible.</p>
        <p>Regards,<br>Security Team</p>
    </body>
    </html>
    """

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

def buffer_event_and_send(contact_email, vendor_first_name, event_data):
    """Buffers events and sends them in batches."""
    global event_buffer
    event_buffer.append(event_data)

    if len(event_buffer) >= EVENT_BATCH_SIZE:  # Check if we have enough events in the buffer
        send_email_to_vendor(contact_email, vendor_first_name, event_buffer)
        event_buffer = []  # Clear the buffer after sending

def flush_buffer():
    """Sends any remaining events in the buffer."""
    if event_buffer:
        contact_email = event_buffer[0]['contact_email']
        vendor_first_name = event_buffer[0]['vendor_first_name']
        send_email_to_vendor(contact_email, vendor_first_name, event_buffer)
        event_buffer.clear()
