import requests
import json

# Splunk HEC configuration
SPLUNK_HEC_URL = "http://127.0.0.1:8077/services/collector"  # Use your Splunk HEC URL
SPLUNK_AUTH_TOKEN = "e493377a-7cb6-4616-8e78-aaa9e75db4df"  # Your HEC token

def send_event_to_splunk(event_data):
    """Sends an event to Splunk using HEC."""
    headers = {
        "Authorization": f"Splunk {SPLUNK_AUTH_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        # Convert event data to JSON
        json_data = json.dumps(event_data)
        response = requests.post(SPLUNK_HEC_URL, headers=headers, data=json_data, verify=False)
        
        if response.status_code == 200:
            print("Event successfully sent to Splunk.")
        else:
            print(f"Failed to send event to Splunk: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending event to Splunk: {e}")

# Example function call
if __name__ == "__main__":
    sample_event = {
        "event": {
            "message": "Sample alert message from Splunk Notifier",
            "severity": "info",
            "timestamp": 1672531200  # Example Unix timestamp
        },
        "sourcetype": "_json",
        "index": "main",
        "source": "http:SBOM_Alert_Notifications"
    }
    
    send_event_to_splunk(sample_event)
