# Enhanced M3U Channel Labeling Guide

## Overview

The enhanced `json_to_m3u.py` script now provides much better channel labeling and categorization for your M3U playlists. This guide explains the new features and how to use them effectively.

## New Features

### 1. Enhanced Channel Labeling
- **Emoji indicators** for visual organization
- **Quality indicators** ([HD], [4K], [60fps], [DRM])
- **Source network indicators** ([ESPN], [FOX], [CBS], [NBC], [ABC])
- **Channel type detection** (News, Sports, Movies, Music, Kids)

### 2. Improved Categorization
The script now supports more categories:
- 🏈 **NFL** - Live NFL games
- 🎫 **Sunday Ticket** - NFL Sunday Ticket
- ⚾ **MLB** - Live MLB games
- 📁 **MLB Archives** - Archived MLB games
- 🏒 **NHL** - Live NHL games
- 🏀 **NBA** - Live NBA games
- 🏠 **NBA Local** - NBA local feeds
- 🔒 **DRM Channels** - DRM-protected channels
- 📺 **Channels** - Regular TV channels

### 3. Channel Type Detection
Regular channels are automatically categorized by type:
- 📰 **News channels** (contains "news")
- 🏆 **Sports channels** (contains "sports")
- 🎬 **Movie channels** (contains "movie" or "cinema")
- 🎵 **Music channels** (contains "music")
- 👶 **Kids channels** (contains "kids" or "children")
- 📺 **General channels** (default)

## Usage Examples

### Basic Usage (Enhanced by default)
```bash
python json_to_m3u.py input.json output.m3u
```
This creates an M3U file with:
- Emoji indicators for groups and channels
- Quality and source indicators
- Channel descriptions included

### Simple Labeling (No enhancements)
```bash
python json_to_m3u.py input.json output.m3u --no-enhanced --no-metadata
```
This creates a basic M3U file similar to the original version.

### Custom Configuration
```bash
# Enhanced labels but no descriptions
python json_to_m3u.py input.json output.m3u --enhanced --no-metadata

# Simple labels but include descriptions
python json_to_m3u.py input.json output.m3u --no-enhanced --with-metadata
```

### With Exclusions
```bash
python json_to_m3u.py input.json output.m3u --exclude "ufc" "nba" "boxing"
```

## Labeling Examples

### Before (Original)
```
#EXTGRP:NFL
#EXTINF:-1,Alt 1 - Commanders @ Chiefs
#EXTINF:-1,ESPN Intl - Commanders @ Chiefs
```

### After (Enhanced)
```
#EXTGRP:🏈 NFL
#EXTINF:-1,🏈 Alt 1 - Commanders @ Chiefs
#EXTINF:-1,🏈 ESPN Intl - Commanders @ Chiefs [ESPN]
```

### Channel Type Examples
```
#EXTINF:-1,📰 CNN News [HD]
#EXTINF:-1,🏆 ESPN Sports [HD] [ESPN]
#EXTINF:-1,🎬 HBO Movies [4K]
#EXTINF:-1,🎵 MTV Music [HD]
#EXTINF:-1,👶 Disney Kids [HD]
```

## Benefits for Your App

### 1. Better Visual Organization
- Emojis make it easy to identify channel types at a glance
- Group headers are more visually appealing
- Consistent formatting across all channels

### 2. Improved Filtering and Search
- Quality indicators help users find HD/4K content
- Source indicators help identify preferred networks
- Channel type emojis enable category-based filtering

### 3. Enhanced User Experience
- More descriptive channel names
- Better grouping for easier navigation
- Professional appearance in media players

### 4. Flexible Configuration
- Choose between enhanced and simple labeling
- Include or exclude metadata as needed
- Maintain backward compatibility

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--enhanced` | Enable enhanced labeling with emojis and indicators | True |
| `--no-enhanced` | Disable enhanced labeling | False |
| `--with-metadata` | Include channel descriptions in titles | True |
| `--no-metadata` | Exclude channel descriptions from titles | False |
| `--exclude TERMS` | Exclude channels containing specified terms | None |

## Tips for App Integration

1. **Parse emojis** to create category filters in your app
2. **Extract quality indicators** to show quality badges
3. **Use source indicators** for network-based filtering
4. **Group by emoji type** for organized channel listings
5. **Parse descriptions** for additional channel information

## Example Output Structure

```
#EXTM3U
#EXTGRP:🏈 NFL
#EXTINF:-1,🏈 NFL Redzone [HD] [ESPN] - Live NFL highlights
https://example.com/stream1
#EXTINF:-1,🏈 NFL Network [HD] - 24/7 NFL coverage
https://example.com/stream2

#EXTGRP:📺 Channels
#EXTINF:-1,📰 CNN News [HD] - Breaking news coverage
https://example.com/stream3
#EXTINF:-1,🎬 HBO Movies [4K] - Premium movie content
https://example.com/stream4
```

This enhanced labeling system will make your M3U playlists much more organized and user-friendly in any media player or streaming app!