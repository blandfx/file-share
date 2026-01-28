#!/usr/bin/env python3
"""
Enhanced JSON to M3U Converter

This script converts JSON data from the seasons4u API format to M3U playlist format
with enhanced channel labeling and improved categorization.

Supported categories:
- Channels (grouped as "Channels")
- NFL (Live) (grouped as "NFL")
- NFL Sunday Ticket (grouped as "Sunday Ticket")
- MLB (Live) (grouped as "MLB")
- MLB (Today's Archives) (grouped as "MLB Archives")
- NHL (Live) (grouped as "NHL")
- NBA DRM (Live) (grouped as "NBA")
- NBA League Pass DRM Local Feeds (grouped as "NBA Local")
- Channels DRM (Live) (grouped as "DRM Channels")

Enhanced Features:
- Emoji indicators for better visual organization
- Quality indicators ([HD], [4K], [60fps], [DRM])
- Source network indicators ([ESPN], [FOX], [CBS], etc.)
- Channel type detection (News, Sports, Movies, Music, Kids)
- Optional metadata inclusion (descriptions)
- Flexible labeling options

The script automatically filters out:
- Channels with "DRM" in the title
- Channels with drmlive=true in their sources
- Channels matching user-specified exclusion terms

Usage:
    python json_to_m3u.py input.json output.m3u
    python json_to_m3u.py input.json output.m3u --exclude "ufc" "nba"
    python json_to_m3u.py input.json output.m3u --no-enhanced --no-metadata
    python json_to_m3u.py input.json output.m3u --enhanced --with-metadata
"""

import json
import argparse
import sys
from pathlib import Path


def load_json_file(file_path):
    """Load and parse JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file '{file_path}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")
        sys.exit(1)


def extract_channels_data(json_data):
    """Extract channels data from multiple categories with improved categorization."""
    channels_by_category = {}
    
    # Navigate through the JSON structure
    if 'googlevideos' in json_data:
        for category in json_data['googlevideos']:
            category_name = category.get('category', '')
            videos = category.get('videos', [])
            
            # Enhanced category mapping with better organization
            if category_name == 'Channels':
                channels_by_category['Channels'] = videos
            elif 'NFL (Live)' in category_name:
                channels_by_category['NFL'] = videos
            elif 'NFL Sunday Ticket' in category_name:
                channels_by_category['Sunday Ticket'] = videos
            elif 'NFL (Week Archives)' in category_name:
                # Skip NFL Archives - not included in output
                continue
            elif category_name == 'MLB (Live)':
                channels_by_category['MLB'] = videos
            elif 'MLB (Today\'s Archives)' in category_name:
                # Add MLB Archives as a separate category
                if 'MLB Archives' not in channels_by_category:
                    channels_by_category['MLB Archives'] = []
                channels_by_category['MLB Archives'].extend(videos)
            elif category_name == 'NHL (Live)':
                channels_by_category['NHL'] = videos
            elif 'NBA DRM (Live)' in category_name:
                channels_by_category['NBA'] = videos
            elif 'NBA League Pass DRM Local Feeds' in category_name:
                # Add NBA Local as a separate category
                if 'NBA Local' not in channels_by_category:
                    channels_by_category['NBA Local'] = []
                channels_by_category['NBA Local'].extend(videos)
            elif 'Channels DRM (Live)' in category_name:
                # Add DRM Channels as a separate category
                if 'DRM Channels' not in channels_by_category:
                    channels_by_category['DRM Channels'] = []
                channels_by_category['DRM Channels'].extend(videos)
    
    return channels_by_category


def should_exclude_channel(title, exclude_terms):
    """Check if a channel should be excluded based on title."""
    if not exclude_terms:
        return False
    
    title_lower = title.lower()
    for term in exclude_terms:
        if term.lower() in title_lower:
            return True
    return False


def has_drm_protection(sources):
    """Check if any source has DRM protection (drmlive=true)."""
    if not sources:
        return False
    
    for source in sources:
        if 'drmlive=true' in source:
            return True
    return False


def should_exclude_drm_channel(title):
    """Check if a channel should be excluded because it contains DRM in title."""
    return 'DRM' in title


def generate_enhanced_channel_title(channel, group_name, include_metadata=True):
    """Generate enhanced channel title with better categorization."""
    title = channel.get('title', '')
    description = channel.get('description', '')
    studio = channel.get('studio', '')
    sources = channel.get('sources', [])
    
    # Extract quality and source information
    quality_info = ""
    source_info = ""
    
    if sources:
        source_url = sources[0]
        if 'drmlive=true' in source_url:
            quality_info = " [DRM]"
        elif '60fps' in source_url.lower():
            quality_info = " [60fps]"
        elif '4k' in source_url.lower():
            quality_info = " [4K]"
        elif 'hd' in source_url.lower():
            quality_info = " [HD]"
        
        # Extract source type from URL
        if 'espn' in source_url.lower():
            source_info = " [ESPN]"
        elif 'fox' in source_url.lower():
            source_info = " [FOX]"
        elif 'cbs' in source_url.lower():
            source_info = " [CBS]"
        elif 'nbc' in source_url.lower():
            source_info = " [NBC]"
        elif 'abc' in source_url.lower():
            source_info = " [ABC]"
    
    # Build enhanced title
    enhanced_title = title
    
    # Add group prefix for better organization
    if group_name == "NFL":
        if "Redzone" in title:
            enhanced_title = f"🏈 NFL Redzone{quality_info}{source_info}"
        elif "NFL Network" in title:
            enhanced_title = f"🏈 NFL Network{quality_info}{source_info}"
        elif "Games" in title:
            enhanced_title = f"🏈 NFL Games{quality_info}{source_info}"
        else:
            enhanced_title = f"🏈 {title}{quality_info}{source_info}"
    elif group_name == "Sunday Ticket":
        enhanced_title = f"🎫 {title}{quality_info}{source_info}"
    elif group_name == "MLB":
        enhanced_title = f"⚾ {title}{quality_info}{source_info}"
    elif group_name == "MLB Archives":
        enhanced_title = f"📁 {title}{quality_info}{source_info}"
    elif group_name == "NHL":
        enhanced_title = f"🏒 {title}{quality_info}{source_info}"
    elif group_name == "NBA":
        enhanced_title = f"🏀 {title}{quality_info}{source_info}"
    elif group_name == "NBA Local":
        enhanced_title = f"🏠 {title}{quality_info}{source_info}"
    elif group_name == "DRM Channels":
        enhanced_title = f"🔒 {title}{quality_info}{source_info}"
    elif group_name == "Channels":
        # Add channel type indicators
        if "news" in title.lower():
            enhanced_title = f"📰 {title}{quality_info}{source_info}"
        elif "sports" in title.lower():
            enhanced_title = f"🏆 {title}{quality_info}{source_info}"
        elif "movie" in title.lower() or "cinema" in title.lower():
            enhanced_title = f"🎬 {title}{quality_info}{source_info}"
        elif "music" in title.lower():
            enhanced_title = f"🎵 {title}{quality_info}{source_info}"
        elif "kids" in title.lower() or "children" in title.lower():
            enhanced_title = f"👶 {title}{quality_info}{source_info}"
        else:
            enhanced_title = f"📺 {title}{quality_info}{source_info}"
    
    # Add metadata if requested and available
    if include_metadata and description and description.strip():
        enhanced_title += f" - {description.strip()}"
    
    return enhanced_title


def generate_m3u_content(channels_by_category, exclude_terms=None, enhanced_labeling=True, include_metadata=True):
    """Generate M3U playlist content from grouped channels data with enhanced labeling."""
    if exclude_terms is None:
        exclude_terms = []
    
    m3u_lines = ["#EXTM3U"]
    
    # Process each category group
    for group_name, channels in channels_by_category.items():
        if not channels:
            continue
            
        # Add group header with emoji for better visual organization
        group_emoji = {
            "NFL": "🏈",
            "Sunday Ticket": "🎫", 
            "MLB": "⚾",
            "MLB Archives": "📁",
            "NHL": "🏒",
            "NBA": "🏀",
            "NBA Local": "🏠",
            "DRM Channels": "🔒",
            "Channels": "📺"
        }.get(group_name, "📺")
        
        m3u_lines.append(f"#EXTGRP:{group_emoji} {group_name}")
        
        # Process channels in this group
        for channel in channels:
            title = channel.get('title', '')
            sources = channel.get('sources', [])
            
            # Skip if title should be excluded by user terms
            if should_exclude_channel(title, exclude_terms):
                continue
            
            # Skip if title contains DRM
            if should_exclude_drm_channel(title):
                continue
            
            # Skip if any source has DRM protection
            if has_drm_protection(sources):
                continue
            
            # Skip if no sources available
            if not sources:
                continue
            
            # Use the first source as the stream URL
            stream_url = sources[0]
            
            # Generate enhanced title if requested
            if enhanced_labeling:
                display_title = generate_enhanced_channel_title(channel, group_name, include_metadata)
            else:
                display_title = title
            
            # Create M3U entry with enhanced formatting
            # Format: #EXTINF:-1,Channel Name
            m3u_lines.append(f"#EXTINF:-1,{display_title}")
            m3u_lines.append(stream_url)
    
    return '\n'.join(m3u_lines)


def save_m3u_file(content, output_path):
    """Save M3U content to file."""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"M3U playlist saved to: {output_path}")
    except Exception as e:
        print(f"Error saving M3U file: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Convert JSON channels data to M3U playlist format with enhanced labeling and grouped categories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python json_to_m3u.py input.json output.m3u
  python json_to_m3u.py input.json output.m3u --exclude "ufc" "nba"
  python json_to_m3u.py input.json output.m3u --exclude "boxing" "wrestling"
  python json_to_m3u.py input.json output.m3u --no-enhanced --no-metadata
  python json_to_m3u.py input.json output.m3u --enhanced --with-metadata
        """
    )
    
    parser.add_argument('input_file', help='Input JSON file path')
    parser.add_argument('output_file', help='Output M3U file path')
    parser.add_argument('--exclude', nargs='*', default=[], 
                       help='Terms to exclude from the playlist (case insensitive)')
    parser.add_argument('--enhanced', action='store_true', default=True,
                       help='Use enhanced channel labeling with emojis and quality indicators (default: True)')
    parser.add_argument('--no-enhanced', dest='enhanced', action='store_false',
                       help='Disable enhanced channel labeling')
    parser.add_argument('--with-metadata', action='store_true', default=True,
                       help='Include channel descriptions in titles (default: True)')
    parser.add_argument('--no-metadata', dest='with_metadata', action='store_false',
                       help='Exclude channel descriptions from titles')
    
    args = parser.parse_args()
    
    # Validate input file exists
    if not Path(args.input_file).exists():
        print(f"Error: Input file '{args.input_file}' does not exist.")
        sys.exit(1)
    
    print(f"Loading JSON data from: {args.input_file}")
    json_data = load_json_file(args.input_file)
    
    print("Extracting channels data...")
    channels_by_category = extract_channels_data(json_data)
    
    if not channels_by_category:
        print("Warning: No channels found in any supported category.")
        sys.exit(1)
    
    # Count total channels across all categories
    total_channels = sum(len(channels) for channels in channels_by_category.values())
    print(f"Found channels in categories: {', '.join(channels_by_category.keys())}")
    print(f"Total channels found: {total_channels}")
    
    if args.exclude:
        print(f"Exclusion terms: {', '.join(args.exclude)}")
    
    print("Generating M3U content...")
    print(f"Enhanced labeling: {'Enabled' if args.enhanced else 'Disabled'}")
    print(f"Include metadata: {'Enabled' if args.with_metadata else 'Disabled'}")
    m3u_content = generate_m3u_content(channels_by_category, args.exclude, args.enhanced, args.with_metadata)
    
    # Count actual channels in the final M3U (excluding header and group headers)
    m3u_lines = m3u_content.split('\n')
    channel_count = sum(1 for line in m3u_lines if line.startswith('#EXTINF:'))
    
    print(f"Generated M3U with {channel_count} channels")
    
    print(f"Saving to: {args.output_file}")
    save_m3u_file(m3u_content, args.output_file)
    
    print("Conversion completed successfully!")


if __name__ == "__main__":
    main()

