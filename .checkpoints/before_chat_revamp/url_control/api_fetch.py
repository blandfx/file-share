import requests
import json
from datetime import datetime

url = "https://seasons4u.com/api2/ATV_Beta_v0_1/List?version=0.99.1"

response = requests.get(url)
data = response.json()

# Get current time in M/D/Y hour:min:sec format
timestamp = datetime.now().strftime('%m-%d-%Y_%H-%M-%S')
filename = f"api_channels_{timestamp}.json"

with open(filename, 'w') as f:
    json.dump(data, f, indent=4)

print(f"Response saved to {filename}")
