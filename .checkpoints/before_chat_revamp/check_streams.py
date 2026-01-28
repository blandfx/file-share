import requests
import re
import time

def check_stream_status(url, timeout=5):
    """
    Checks the status of a stream URL using an HTTP HEAD request.

    Args:
        url (str): The URL of the stream to check.
        timeout (int): Request timeout in seconds.

    Returns:
        str: 'Alive' if the stream responds successfully (2xx status code),
             'Dead' otherwise (includes timeouts, connection errors, non-2xx codes).
    """
    try:
        # Use HEAD request to check availability without downloading content
        # Allow redirects as streams might redirect
        # stream=True might be useful for some stream types if HEAD fails,
        # but HEAD is generally sufficient and faster for checking basic reachability.
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        # Consider any 2xx status code as 'Alive'
        if response.status_code >= 200 and response.status_code < 300:
            return "Alive"
        else:
            # You could log response.status_code here for more detail
            return "Dead (Status: {})".format(response.status_code)
    except requests.exceptions.Timeout:
        return f"Dead (Timeout > {timeout}s)"
    except requests.exceptions.RequestException as e:
        # Catches connection errors, invalid URLs, etc.
        # You could log the specific error 'e' for debugging
        return f"Dead (Error)"
    except Exception as e:
        # Catch any other unexpected errors
        return f"Dead (Unexpected Error)"


def parse_m3u(filename="channels_playlist.m3u"):
    """
    Parses an M3U file, extracts channel names and URLs,
    and checks the status of each stream URL.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        return

    channel_name = None
    print(f"Checking streams in {filename}...\n")

    for line in lines:
        line = line.strip()
        if line.startswith('#EXTINF:'):
            # Extract channel name (part after the comma)
            match = re.search(r",(.+)$", line)
            if match:
                channel_name = match.group(1)
            else:
                channel_name = "Unknown Name" # Fallback if format is unexpected
        elif line.startswith('http'):
            if channel_name:
                url = line
                status = check_stream_status(url)
                print(f"{channel_name}: {status} ({url})")
                # Reset channel_name for the next entry
                channel_name = None
                # Optional: Add a small delay between requests to avoid overwhelming the server
                # time.sleep(0.1)
            else:
                # URL found without preceding #EXTINF - might be header info or malformed file
                print(f"Found URL without channel info: {line}")
        # Ignore other lines (#EXTM3U, blank lines, etc.)

    print("\nCheck complete.")

if __name__ == "__main__":
    # Create a dummy channels_playlist.m3u file for testing if it doesn't exist
    # In a real scenario, you would have your actual M3U file.
    try:
        with open("channels_playlist.m3u", "x", encoding='utf-8') as f:
            f.write("""#EXTM3U
#EXTINF:-1, Fox Soccer Plus
https://seasons4u.com/api2/ATV_Beta_v0_1/Watch_CHN/605
#EXTINF:-1, ESPN
https://seasons4u.com/api2/ATV_Beta_v0_1/Watch_CHN/5000
#EXTINF:-1, ESPN 2
https://seasons4u.com/api2/ATV_Beta_v0_1/Watch_CHN/5001
#EXTINF:-1, Example Valid URL (Google)
https://www.google.com
#EXTINF:-1, Example Invalid URL
https://thissitedoesnotexist.invalid/stream
#EXTINF:-1, Example Timeout URL (adjust timeout in script if needed)
http://httpbin.org/delay/10
""")
            print("Created dummy channels_playlist.m3u for testing.")
    except FileExistsError:
        pass # File already exists, proceed

    parse_m3u("channels_playlist.m3u")
