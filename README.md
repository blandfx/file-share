# File Share

A Flask-based file sharing application designed for personal use, running on Synology NAS.

## Features

- **File Browsing**: Browse files and directories with a clean, responsive interface.
- **Video Streaming**: Stream video files directly in the browser with transcoding support (FFmpeg).
- **Mobile Optimized**: Includes mobile-friendly navigation and "pull-to-refresh" functionality.
- **Authentication**: Secure access with login protection.
- **File Management**: Rename, delete, and upload files directly from the interface.
- **Download Management**: Integrates with external tools for downloading content.
- **Notes**: Create and edit notes.

## Setup

1.  **Dependencies**:
    -   Python 3.11+
    -   Flask
    -   FFmpeg (for video transcoding)
    -   Other requirements listed in `app.py` imports.

2.  **Configuration**:
    -   The application is configured to run on a Synology NAS environment.
    -   Key paths (like `/mnt/synology/misc/media/`) are hardcoded in `app.py` and may need adjustment for other environments.

3.  **Running the App**:
    ```bash
    python app.py
    ```

## Project Structure

-   `app.py`: Main Flask application logic.
-   `templates/`: HTML templates for the web interface.
-   `static/`: CSS, JavaScript, and icons.
-   `url_control/`: Scripts for managing URL-based content (e.g., IPTV).

## License

Private / Personal Use.
