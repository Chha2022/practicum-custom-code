import http.server
import ssl

# Webhook Listener Configuration
HOST = 'localhost'
PORT = 8888
API_TOKEN = 'xRb9PqJvNf5sA2wLz7hG0cVeUq1yRnKd'

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

        # Log the received data
        print(f"Received POST request: {post_data.decode('utf-8')}")

        # Send a 200 OK response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Webhook received successfully')

# Create an HTTP server
httpd = http.server.HTTPServer((HOST, PORT), WebhookHandler)

# Create an SSL context for HTTPS
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# Wrap the server socket with SSL
httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

print(f"HTTPS Server running on https://{HOST}:{PORT}")
httpd.serve_forever()
