#!/usr/bin/env python3
"""
Download static assets for offline documentation (Swagger UI, ReDoc, fonts)
This ensures the application works without external CDN dependencies.
"""

import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Define asset URLs and local paths
ASSETS = [
    {
        "name": "Swagger UI CSS",
        "url": "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        "path": "static/swagger-ui/swagger-ui.css"
    },
    {
        "name": "Swagger UI JS",
        "url": "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        "path": "static/swagger-ui/swagger-ui-bundle.js"
    },
    {
        "name": "Swagger UI Standalone",
        "url": "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js",
        "path": "static/swagger-ui/swagger-ui-standalone-preset.js"
    },
    {
        "name": "ReDoc Standalone",
        "url": "https://unpkg.com/redoc@latest/bundles/redoc.standalone.js",
        "path": "static/redoc/redoc.standalone.js"
    },
    {
        "name": "Google Fonts CSS (Montserrat, Roboto)",
        "url": "https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;700&family=Roboto:wght@300;400;700&display=swap",
        "path": "static/fonts/google-fonts.css"
    }
]

def download_file(url, local_path):
    """Download a file from URL to local path."""
    try:
        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        
        print(f"  Downloading: {url}")
        urllib.request.urlretrieve(url, local_path)
        print(f"  ✅ Saved to: {local_path}")
        return True
    except urllib.error.URLError as e:
        print(f"  ❌ Error downloading {url}: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False

def main():
    """Download all static assets."""
    script_dir = Path(__file__).parent
    backend_dir = script_dir.parent
    os.chdir(backend_dir)
    
    print("📥 Downloading static assets for offline documentation...\n")
    
    success_count = 0
    failed_count = 0
    
    for asset in ASSETS:
        print(f"Downloading: {asset['name']}")
        if download_file(asset['url'], asset['path']):
            success_count += 1
        else:
            failed_count += 1
        print()
    
    print("=" * 60)
    print(f"✅ Successfully downloaded: {success_count} assets")
    if failed_count > 0:
        print(f"❌ Failed: {failed_count} assets")
        print("\n⚠️  WARNING: Some assets could not be downloaded.")
        print("The application may not have full documentation access.")
    else:
        print("✅ All assets downloaded successfully!")
    print("=" * 60)
    
    return 0 if failed_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
