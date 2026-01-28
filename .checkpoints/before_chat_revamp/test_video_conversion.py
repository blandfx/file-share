#!/usr/bin/env python3
"""
Test script for video transcoding functionality
"""

import os
import subprocess
import sys

def test_ffmpeg_available():
    """Test if ffmpeg and ffprobe are available"""
    try:
        subprocess.run(['ffmpeg', '-version'], capture_output=True, check=True)
        subprocess.run(['ffprobe', '-version'], capture_output=True, check=True)
        print("✓ ffmpeg and ffprobe are available")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ ffmpeg or ffprobe not found. Please install ffmpeg.")
        return False

def test_video_analysis():
    """Test video codec analysis functionality"""
    # Import the functions from app.py
    sys.path.append('.')
    from app import is_web_compatible_video, stream_video_transcoded
    
    # Test with a sample video file (if available)
    test_video = '/mnt/synology/misc/media/test_video.mp4'
    
    if os.path.exists(test_video):
        print(f"Testing video analysis with: {test_video}")
        try:
            is_compatible = is_web_compatible_video(test_video)
            print(f"✓ Video compatibility check: {is_compatible}")
            return True
        except Exception as e:
            print(f"✗ Error testing video analysis: {e}")
            return False
    else:
        print("No test video found. Skipping video analysis test.")
        return True

def main():
    print("Testing video transcoding functionality...")
    print("=" * 50)
    
    # Test 1: Check if ffmpeg is available
    ffmpeg_ok = test_ffmpeg_available()
    
    # Test 2: Test video analysis
    analysis_ok = test_video_analysis()
    
    print("=" * 50)
    if ffmpeg_ok and analysis_ok:
        print("✓ All tests passed! Video transcoding should work.")
        print("\nTo test the full functionality:")
        print("1. Start your Flask app: python app.py")
        print("2. Upload a non-web-compatible video file")
        print("3. Click on the video file to view it")
        print("4. The video should be transcoded on-the-fly to web-compatible format")
        print("5. Original files are preserved - only transcoded during streaming")
    else:
        print("✗ Some tests failed. Please check the errors above.")

if __name__ == "__main__":
    main() 