import http.server
import ssl
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Webhook Listener Configuration
HOST = 'localhost'
PORT = 8888
API_TOKEN = 'xRb9PqJvNf5sA2wLz7hG0cVeUq1yRnKd'

# Mock SMTP Configuration (Assuming SMTP server is localhost)
SMTP_SERVER = 'localhost'
SMTP_PORT = 25
SMTP_USER = 'user@example.com'
SMTP_PASSWORD = 'password'

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # Check for the required API token in headers
        api_key = self.headers.get('X-Api-Key')
        if api_key != API_TOKEN:
            self.send_response(401)  # Unauthorized
            self.end_headers()
            self.wfile.write(b'Unauthorized')
            return

        # Read the content length
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Parse incoming webhook JSON data
        try:
            notification = json.loads(post_data.decode('utf-8'))
            print(f"Received notification: {json.dumps(notification, indent=2)}")
            
            # Extract vendor contact details (assuming the keys exist in the payload)
            vendor_first_name = notification.get("vendorFirstName", "N/A")
            vendor_last_name = notification.get("vendorLastName", "N/A")
            vendor_email = notification.get("vendorEmail", "N/A")
            vulnerability_info = notification.get("vulnerabilityInfo", "No details provided")

            # Format an email message to the vendor
            subject = "New Vulnerability Alert for Your Project"
            body = f"""
            Hi {vendor_first_name} {vendor_last_name},

            We have identified new vulnerabilities associated with your project. 

            Details:
            {vulnerability_info}

            Please review the vulnerabilities at your earliest convenience.

            Regards,
            Security Team
            """

            # Send the email to the vendor
            self.send_email(vendor_email, subject, body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Webhook received and email sent successfully')

        except json.JSONDecodeError:
            self.send_response(400)  # Bad Request
            self.end_headers()
            self.wfile.write(b'Invalid JSON format')

    def send_email(self, recipient_email, subject, body):
        # Set up the MIME email message
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = recipient_email
        msg['Subject'] = subject

        # Attach the email body
        msg.attach(MIMEText(body, 'plain'))

        try:
            # Connect to the SMTP server and send the email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, recipient_email, msg.as_string())
                print(f"Email sent to {recipient_email}")
        except Exception as e:
            print(f"Failed to send email: {e}")

# Create an HTTP server
httpd = http.server.HTTPServer((HOST, PORT), WebhookHandler)

# Create an SSL context for HTTPS
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# Wrap the server socket with SSL
httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

print(f"HTTPS Server running on https://{HOST}:{PORT}")
httpd.serve_forever()
