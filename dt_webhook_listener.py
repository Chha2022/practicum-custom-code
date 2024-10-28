from http.server import BaseHTTPRequestHandler, HTTPServer
import json

# Webhook listener settings
HOST_NAME = "localhost"
PORT_NUMBER = 8888

# Static API token for security
API_TOKEN = "xRb9PqJvNf5sA2wLz7hG0cVeUq1yRnKd"

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Check for the API token in the headers
        auth_header = self.headers.get('X-Api-Key')
        if auth_header != API_TOKEN:
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"Forbidden: Invalid API token")
            return
        
        # Get content length to read the body of the request
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        # Parse the incoming JSON data
        try:
            payload = json.loads(post_data)
            print("\n=== Webhook Received ===")
            print(json.dumps(payload, indent=4))  # Pretty print JSON payload
            self.send_response(200)  # OK
            self.end_headers()
            self.wfile.write(b"Webhook received successfully")
        except json.JSONDecodeError:
            self.send_response(400)  # Bad Request
            self.end_headers()
            self.wfile.write(b"Invalid JSON payload")
    
    def log_message(self, format, *args):
        # Override to disable default logging to the console
        return

def run_server():
    server_address = (HOST_NAME, PORT_NUMBER)
    httpd = HTTPServer(server_address, WebhookHandler)
    print(f"Server running at http://{HOST_NAME}:{PORT_NUMBER}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
