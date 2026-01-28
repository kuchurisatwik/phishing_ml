import os, re
import tldextract
import numpy as np
from PIL import Image, ImageDraw
import sys, asyncio
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
 

from .config import SCREENS_DIR
from .features import (
    extract_url_features,
    extract_subdomain_features,
    extract_path_features,
    entropy_features,
    ssl_features,
    get_ip_address,
)
from .visual_features import (
    capture_screenshot,
    branding_guidelines_features,
    extract_ocr_text,
    laplacian_variance,
    get_favicon_features,
)

def ensure_dirs():
    os.makedirs(SCREENS_DIR, exist_ok=True)

def extract_all_features(url, csv_file=None):
    
    ensure_dirs()

    ext = tldextract.extract(url)
    domain_full = ".".join(part for part in [ext.domain, ext.suffix] if part) or url
    screenshot_path = os.path.join(SCREENS_DIR, f"{domain_full}.png")


    target_url, capture_ok = capture_screenshot(url, screenshot_path)

    if not capture_ok:
        img = Image.new("RGB", (1280, 720), color=(255, 255, 255))
        d = ImageDraw.Draw(img)
        d.text((20, 30), f"Failed to capture: {url}", fill=(0, 0, 0))
        img.save(screenshot_path)

    url_feats       = extract_url_features(target_url)
    subdomain_feats = extract_subdomain_features(target_url)
    path_feats      = extract_path_features(target_url)
    entropy_feats   = entropy_features(target_url)
    ssl_feats       = ssl_features(target_url)
    ip_addr         = get_ip_address(target_url)

    branding_feats = {"brand_colors": [], "avg_color_diff": -1.0, "logo_hash": None, "logo_match_score": -1}
    ocr_text = ""
    lap_var = float("nan")

    try:
        branding_feats = branding_guidelines_features(screenshot_path)
    except Exception as e:
        print(f"⚠ Branding extraction failed: {e}")
    try:
        ocr_text = extract_ocr_text(screenshot_path)
    except Exception as e:
        print(f"⚠ OCR failed: {e}")
    try:
        lap_var = laplacian_variance(screenshot_path)
    except Exception as e:
        print(f"⚠ Laplacian variance failed: {e}")

    fav_feats = get_favicon_features(target_url)
    fav_feats.pop("favicon_path", None)

    all_feats = {
        "url": target_url,
        "ip_address": ip_addr,
        **url_feats,
        **subdomain_feats,
        **path_feats,
        **entropy_feats,
        **ssl_feats,
        **branding_feats,
        **fav_feats,
        "ocr_text": ocr_text,
        "laplacian_variance": lap_var
    }

    return all_feats, screenshot_path
