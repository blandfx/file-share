# Video Transcoding System

## Overview

This Flask application now includes automatic on-the-fly video transcoding for web compatibility. Instead of converting video files permanently, the system transcodes videos in real-time when they are accessed, preserving the original files.

## How It Works

### 1. Video Compatibility Detection

The system automatically detects if a video file is web-compatible by checking:
- **Video codecs**: h264, vp8, vp9, av1
- **Audio codecs**: aac, mp3, vorbis, opus  
- **Container formats**: mp4, webm, m4v

### 2. On-the-Fly Transcoding

When a non-web-compatible video is accessed:
- The video is transcoded in real-time using FFmpeg
- Output format: MP4 with H.264 video and AAC audio
- Optimized for streaming with faststart flags
- Supports HTTP range requests for seeking

### 3. Supported Video Formats

The system handles these video formats:
- `.mp4`, `.webm`, `.avi`, `.mkv`, `.mov`, `.wmv`, `.flv`, `.m4v`

## Technical Details

### FFmpeg Command Used

```bash
ffmpeg -i input_file -ss start_time -c:v libx264 -preset ultrafast -crf 23 -c:a aac -b:a 128k -movflags +faststart -avoid_negative_ts make_zero -f mp4 pipe:1
```

### Key Parameters

- **`-preset ultrafast`**: Fastest encoding for real-time streaming
- **`-crf 23`**: Good quality with reasonable file size
- **`-movflags +faststart`**: Optimizes for web streaming
- **`-avoid_negative_ts make_zero`**: Handles seeking properly
- **`pipe:1`**: Outputs to stdout for streaming

## Benefits

1. **Preserves Original Files**: No permanent conversion, original files stay intact
2. **Automatic**: No manual intervention required
3. **Web Compatible**: All videos play directly in browsers
4. **Efficient**: Only transcodes when needed
5. **Seeking Support**: HTTP range requests work for video seeking

## Requirements

- FFmpeg installed on the system
- Sufficient CPU resources for real-time transcoding
- Adequate bandwidth for streaming

## Usage

1. Upload any video file to your media directory
2. Access the video through the web interface
3. The system automatically detects if transcoding is needed
4. If needed, the video is transcoded on-the-fly and streamed
5. Original file remains unchanged

## Performance Considerations

- **CPU Usage**: Transcoding is CPU-intensive, especially for large files
- **Memory**: Uses buffered streaming to manage memory usage
- **Bandwidth**: Transcoding happens in real-time, so initial buffering may occur
- **Concurrent Users**: Multiple simultaneous transcoding sessions will increase server load

## Troubleshooting

### Common Issues

1. **FFmpeg not found**: Install FFmpeg on your system
2. **High CPU usage**: Consider using a more powerful server or pre-converting frequently accessed videos
3. **Buffering issues**: Check network bandwidth and server resources
4. **Seeking not working**: Ensure HTTP range requests are properly configured

### Logs

Check the application logs for transcoding information:
- `logger.info()` messages show when transcoding starts
- `logger.error()` messages show transcoding failures
- `logger.debug()` messages show detailed codec information

## Future Enhancements

- Caching transcoded segments for better performance
- Adaptive bitrate streaming
- Support for more output formats
- Background pre-transcoding for frequently accessed videos 