import os, re, base64, mimetypes, requests
import numpy as np, cv2, imagehash
from PIL import Image
from urllib.parse import urlparse
from sklearn.cluster import KMeans
from colormath.color_objects import LabColor, sRGBColor
from colormath.color_conversions import convert_color
from colormath.color_diff import delta_e_cie2000
from playwright.sync_api import sync_playwright, Playwright, Browser, BrowserContext
import tldextract
import easyocr
import torch
import logging

from .config import SCREENS_DIR

# ------------------ Global "Lazy" Initializers ------------------
# We initialize these to None. They will be created on-demand
# by the getter functions below, ensuring they only load when used.

_play: Playwright | None = None
_browser: Browser | None = None
_context: BrowserContext | None = None
_ocr_reader: easyocr.Reader | None = None

logger = logging.getLogger(__name__)

def _get_browser_context() -> BrowserContext:
    """
    Initializes and returns a single, shared Playwright browser context.
    This function ensures Playwright only starts when it's first needed.
    """
    global _play, _browser, _context
    
    # If we've already initialized it, just return the existing context
    if _context:
        return _context

    try:
        logger.info("🚀 Initializing Playwright browser for the first time...")
        _play = sync_playwright().start()
        _browser = _play.chromium.launch(headless=True)
        _default_viewport = {"width": 1280, "height": 900}
        _context = _browser.new_context(viewport=_default_viewport)
        logger.info("✅ Playwright browser context is ready.")
        return _context
    except Exception as e:
        logger.error("❌ Failed to initialize Playwright browser: %s", e)
        # Re-raise the exception to stop the process if the browser is critical
        raise

def _get_ocr_reader() -> easyocr.Reader:
    """
    Initializes and returns a single, shared EasyOCR reader.
    This function ensures the model only loads when it's first needed.
    """
    global _ocr_reader
    
    # If we've already initialized it, just return the existing reader
    if _ocr_reader:
        return _ocr_reader

    try:
        logger.info("🚀 Initializing EasyOCR reader for the first time (this may take a moment)...")
        _ocr_reader = easyocr.Reader(['en'], gpu=torch.cuda.is_available())
        logger.info("✅ EasyOCR reader is ready.")
        return _ocr_reader
    except Exception as e:
        logger.error("❌ Failed to initialize EasyOCR reader: %s", e)
        # Return a "None" or raise an error, depending on desired failure mode.
        # For this project, we'll re-raise to make failure obvious.
        raise

def close_browser():
    """Cleanly close browser + context when done."""
    global _play, _browser, _context
    
    # Only try to close if they were actually initialized
    if _context:
        try:
            _context.close()
            _context = None
        except Exception as e:
            logger.warning("Error closing Playwright context: %s", e)
    if _browser:
        try:
            _browser.close()
            _browser = None
        except Exception as e:
            logger.warning("Error closing Playwright browser: %s", e)
    if _play:
        try:
            _play.stop()
            _play = None
        except Exception as e:
            logger.warning("Error stopping Playwright: %s", e)
    
    logger.info("💤 Playwright browser has been closed.")

# ------------------ Screenshot ------------------
def capture_screenshot(url, out_file, width=1280, height=900):
    try:
        if not url.startswith("http"):
            try_urls = [f"https://{url}", f"http://{url}"]
        else:
            try_urls = [url]

        # --- Use the getter function to ensure browser is running ---
        context = _get_browser_context()
        page = context.new_page()
        
        for target in try_urls:
            try:
                page.goto(target, timeout=5000)  # ⏱ reduced timeout
                page.screenshot(path=out_file, full_page=True)
                page.close()
                return target, True
            except Exception:
                continue
        page.close()
        return try_urls[-1], False
    except Exception as e:
        logger.warning("⚠ Screenshot failed for %s: %s", url, e)
        return url, False

# ------------------ Brand Colors ------------------
def extract_brand_colors(image_path, num_colors=3):
    try:
        img = Image.open(image_path).convert("RGB")
        npimg = np.array(img)
        # ⚡ speed up by downsampling
        npimg = cv2.resize(npimg, (150, 150))
        pixels = npimg.reshape((-1, 3))
        kmeans = KMeans(n_clusters=num_colors, n_init="auto", random_state=42)
        kmeans.fit(pixels)
        centers = kmeans.cluster_centers_.astype(int).tolist()
        return centers
    except Exception:
        return []

def branding_guidelines_features(image_path, brand_colors=None, brand_logo_hash=None):
    info = {
        "brand_colors": [],
        "avg_color_diff": -1.0,
        "logo_hash": None,
        "logo_match_score": -1
    }
    try:
        img = Image.open(image_path).convert("RGB")
        info["brand_colors"] = extract_brand_colors(image_path, 3)
        ph = imagehash.phash(img)
        info["logo_hash"] = str(ph)
        if brand_logo_hash and hasattr(brand_logo_hash, "hash") and brand_logo_hash.hash.shape == ph.hash.shape:
            info["logo_match_score"] = ph - brand_logo_hash
        if brand_colors:
            try:
                ref_labs = [convert_color(sRGBColor(*c, is_upscaled=True), LabColor) for c in brand_colors]
                dom_labs = [convert_color(sRGBColor(*c, is_upscaled=True), LabColor) for c in info["brand_colors"]]
                dists = []
                for dl in dom_labs:
                    dists.extend([delta_e_cie2000(dl, rl) for rl in ref_labs])
                if dists:
                    info["avg_color_diff"] = float(np.mean(dists))
            except Exception:
                info["avg_color_diff"] = -1.0
    except Exception:
        pass
    return info

# ------------------ Favicon ------------------
def _save_favicon_from_data_url(data_url, dst_basename):
    header, encoded = data_url.split(",", 1)
    mime = re.match(r"data:(.*?);base64", header).group(1)
    ext = mimetypes.guess_extension(mime) or ".ico"
    out_path = os.path.join(SCREENS_DIR, f"{dst_basename}_favicon{ext}")
    with open(out_path, "wb") as f:
        f.write(base64.b64decode(encoded))
    return out_path

def detect_favicon_sync(domain_or_url):
    url = domain_or_url if domain_or_url.startswith("http") else "https://" + domain_or_url
    try:
        # --- Use the getter function to ensure browser is running ---
        context = _get_browser_context()
        page = context.new_page()
        
        page.goto(url, timeout=5000)  # ⏱ reduced timeout
        icons = page.locator("link[rel*='icon']").evaluate_all("els => els.map(el => el.href)")
        page.close()
        if icons and len(icons) > 0:
            return True, icons[0]
        else:
            parsed = urlparse(url)
            return True, f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    except Exception:
        return False, None

def get_favicon_features(url):
    feats = {
        "favicon_detected": False,
        "favicon_url": None,
        "favicon_size": -1,
        "favicon_hash": None,
        "favicon_colors": []
    }
    has_fav, icon_url = detect_favicon_sync(url)
    feats["favicon_detected"] = bool(has_fav and icon_url)
    feats["favicon_url"] = icon_url
    if not feats["favicon_detected"]:
        return feats

    try:
        parsed = tldextract.extract(url)
        base = parsed.domain or "site"
        if icon_url and icon_url.startswith("data:image"):
            path = _save_favicon_from_data_url(icon_url, base)
        else:
            resp = requests.get(icon_url, timeout=8, stream=True)
            if resp.status_code != 200 or len(resp.content) < 50:
                return feats
            ext = os.path.splitext(urlparse(icon_url).path)[-1] or ".ico"
            path = os.path.join(SCREENS_DIR, f"{base}_favicon{ext}")
            with open(path, "wb") as f:
                f.write(resp.content)

        img = Image.open(path).convert("RGB").resize((32, 32)) # Standardize size
        feats["favicon_size"] = str(img.size)
        feats["favicon_hash"] = str(imagehash.phash(img))
        feats["favicon_colors"] = extract_brand_colors(path, 3)
        # feats["favicon_path"] = path # No need to keep this in the final features
    except Exception:
        pass
    return feats

# ------------------ OCR (EasyOCR) ------------------
def extract_ocr_text(image_path):
    try:
        # --- Use the getter function to ensure the model is loaded ---
        reader = _get_ocr_reader()
        
        results = reader.readtext(image_path, detail=0)  # detail=0 → only text
        txt = " ".join(results)
        txt = re.sub(r"\s+", " ", txt).strip()
        return txt
    except Exception as e:
        logger.warning("⚠ OCR extraction failed for %s: %s", image_path, e)
        return ""

# ------------------ Sharpness ------------------
def laplacian_variance(image_path, min_size=50):
    try:
        img = cv2.imread(image_path)
        if img is None:
            logger.warning("Could not read image for laplacian: %s", image_path)
            return float("nan")
            
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        variances = []
        for cnt in contours:
            x, y, w, h = cv2.boundingRect(cnt)
            if w < min_size or h < min_size:
                continue
            roi = gray[y:y+h, x:x+w]
            variances.append(cv2.Laplacian(roi, cv2.CV_64F).var())
        
        if variances:
            return float(np.mean(variances))
        
        # Fallback to full image if no large-enough contours are found
        return float(cv2.Laplacian(gray, cv2.CV_64F).var())
    except Exception as e:
        logger.warning("⚠ Laplacian variance failed for %s: %s", image_path, e)
        return float("nan")