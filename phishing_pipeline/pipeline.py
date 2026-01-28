import sys, asyncio, re, os, socket, whois, dns.resolver, logging
import pandas as pd
import tldextract
from datetime import datetime
from dateutil import parser
import warnings
from urllib.parse import urlparse
from fpdf import FPDF

# NEW: visual analysis imports
import cv2, imagehash
import numpy as np
from PIL import Image
# We have REMOVED pytesseract, as it's no longer used.
# EasyOCR in visual_features.py handles all text extraction now.

from .config import (
    FEATURES_CSV, FEATURES_ENRICH, FINAL_OUTPUT,
    ASN_DB_PATH, CITY_DB_PATH, SCREENS_DIR,
    EVIDENCE_DIR, APPLICATION_ID
)
from .utils import extract_all_features
from .geoip_utils import enrich_with_geoip
from .model_utils import load_models_and_preproc
from .shortlisting import generate_shortlisted_csv

# ---
# --- FIX 1: Define ROOT_DIR at the top so all functions can use it.
# ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
# --- (End of Fix 1) ---

warnings.filterwarnings("ignore", message=".*pin_memory.*")

# ------------------------------------------------------------------
# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("phishing_pipeline")
logger.propagate = False

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# ------------------------------------------------------------------
# Source mapping & brand config
# ------------------------------------------------------------------
SOURCE_MAPPING = {
    "sbi": "Banking/Financial", "icici": "Banking/Financial", "hdfc": "Banking/Financial",
    "pnb": "Banking/Financial", "bankof": "Banking/Financial", "bob": "Banking/Financial",
    "canara": "Banking/Financial", "axis": "Banking/Financial", "kotak": "Banking/Financial",
    "yesbank": "Banking/Financial", "unionbank": "Banking/Financial", "idbi": "Banking/Financial",
    "indus": "Banking/Financial", "sbicard": "Banking/Financial", "card": "Banking/Financial",
    "pay": "Banking/Financial",
    "life": "Insurance", "lombard": "Insurance", "prulife": "Insurance",
    "ergo": "Insurance", "insurance": "Insurance", "lic": "Insurance",
    "gov": "Government", "nic": "Government", "mgovcloud": "Government",
    "crsorgi": "Government", "kavach": "Government",
    "irctc": "Transport", "rail": "Transport", "railway": "Transport",
    "airtel": "Telecom", "vodafone": "Telecom", "reliance": "Telecom",
    "iocl": "Oil & Gas", "hpcl": "Oil & Gas", "bpcl": "Oil & Gas",
    "ongc": "Oil & Gas", "oil": "Oil & Gas", "petrol": "Oil & Gas",
    "accounts": "Services", "email": "Services",
    "facebook": "Social Media", "fb": "Social Media",
    "instagram": "Social Media", "insta": "Social Media",
    "twitter": "Social Media", "x": "Social Media",
    "linkedin": "Social Media", "lnkd": "Social Media",
    "reddit": "Social Media", "rdt": "Social Media",
    "youtube": "Social Media", "yt": "Social Media",
    "tiktok": "Social Media", "tk": "Social Media",
    "telegram": "Social Media", "whatsapp": "Social Media"
}

HIGH_PRIORITY_TOKENS = {"irctc", "nic", "iocl", "sbi", "icici", "hdfc", "airtel"}

# Brand visual palettes (extendable)
# NOTE: This is no longer used by reclassify_label but kept for future reference
BRAND_COLORS = {
    "sbi": [(10, 60, 105)],    # SBI blue
    "airtel": [(228, 0, 43)], # Airtel red
    "irctc": [(0, 85, 150)],  # IRCTC blue
    "nic": [(0, 51, 153)],    # NIC blue
    "iocl": [(255, 102, 0)],  # IOC orange
}

BRAND_KEYWORDS = {"sbi", "airtel", "irctc", "nic", "iocl", "baroda"}

TRUSTED_REGISTRARS = {"godaddy", "gmo internet", "markmonitor", "verisign"}
SUSPICIOUS_REGISTRARS = {"namecheap", "freenom", "dynadot", "pdr ltd"}

TRUSTED_HOSTS = {"amazon", "akamai", "cloudflare", "microsoft", "google"}
SUSPICIOUS_HOSTS = {"hostinger", "ovh", "contabo", "digitalocean"}

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def normalize_text(s):
    if s is None:
        return ""
    return re.sub(r"[^a-z0-9]", " ", str(s).lower()).strip()

def domain_tokens_from_url(url):
    try:
        ext = tldextract.extract(url)
        tokens = []
        if ext.subdomain: tokens += [p for p in ext.subdomain.split(".") if p]
        if ext.domain: tokens.append(ext.domain)
        if ext.suffix: tokens.append(ext.suffix.replace(".", ""))
        return [t.lower() for t in tokens if t]
    except Exception:
        return [t for t in re.split(r"[\W_]+", str(url).lower()) if t]

def adjust_source(org_name, whitelisted_domain, ml_source="Unknown"):
    org_norm = normalize_text(org_name)
    dom_tokens = domain_tokens_from_url(whitelisted_domain)
    for tok in HIGH_PRIORITY_TOKENS:
        if tok in org_norm or tok in dom_tokens:
            return SOURCE_MAPPING.get(tok, ml_source)
    for tok in dom_tokens:
        if tok in SOURCE_MAPPING:
            return SOURCE_MAPPING[tok]
    for key, mapped in SOURCE_MAPPING.items():
        if key in org_norm or key in whitelisted_domain.lower():
            return mapped
    return ml_source
# ------------------------------------------------------------------
# Feature extraction
# ------------------------------------------------------------------
def process_urls(input_csv, output_csv=FEATURES_CSV):
    """Extract features for each candidate domain."""
    import csv
    df = pd.read_csv(input_csv)
    logger.info("⚙️ Extracting features for %d domains", len(df))
    with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
        writer = None
        for idx, row in df.iterrows():
            # --- Use the new column name ---
            domain = row["Identified Phishing/Suspected Domain Name"]
            logger.info("[%d/%d] 🔎 Extracting features for %s", idx + 1, len(df), domain)
            try:
                feats, _ = extract_all_features(domain)
                record = {
                    # --- Use the new column names ---
                    "Cooresponding CSE": row["Cooresponding CSE"],
                    "Legitimate Domains": row["Legitimate Domains"],
                    **feats
                }
                if writer is None:
                    writer = csv.DictWriter(f, fieldnames=list(record.keys()))
                    writer.writeheader()
                writer.writerow(record)
                logger.info("✅ Features extracted for %s", domain)
            except Exception as e:
                logger.error("❌ Failed feature extraction for %s — %s", domain, e)
    return output_csv

# ------------------------------------------------------------------
# Visual feature extraction (REMOVED)
# ---
# --- All visual feature extraction (pytesseract) is removed from here.
# --- It is now 100% handled by visual_features.py (EasyOCR)
# --- and utils.py, which saves features to the CSV.
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# Evidence handling
# ------------------------------------------------------------------
def format_evidence_filename(org_name: str, domain: str, serial_no: int, application_id: str = APPLICATION_ID):
    import re, tldextract
    org_tag = re.findall(r"\((.*?)\)", org_name)
    org_tag = org_tag[0] if org_tag else org_name.split()[0]
    ext = tldextract.extract(domain)
    two_level = ".".join(part for part in [ext.domain, ext.suffix] if part)
    filename = f"{org_tag}_{two_level}_{serial_no}.pdf"
    folder = EVIDENCE_DIR
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename), os.path.join(os.path.basename(folder), filename)

def move_screenshot_to_evidence(domain_url, pdf_path):
    try:
        ext = tldextract.extract(domain_url)
        # --- FIX: Re-create the domain part correctly ---
        domain_part = ext.domain or ""
        suffix_part = ext.suffix or ""
        if not domain_part: # Handle cases like 'http://1.2.3.4'
             domain_full = domain_url.replace("https://","").replace("http://","").split("/")[0]
        else:
            domain_full = ".".join(part for part in [domain_part, suffix_part] if part)
        
        screenshot_path = os.path.join(SCREENS_DIR, f"{domain_full}.png")
        if not os.path.exists(screenshot_path):
            logger.warning("⚠️ Screenshot file not found: %s", screenshot_path)
            return False
        
        pdf = FPDF()
        pdf.add_page()
        
        # Add image, handling different sizes
        try:
            with Image.open(screenshot_path) as img:
                w, h = img.width, img.height
                # A4 page is 210mm wide, 190mm usable (10mm margin)
                img_w = 190
                img_h = (h * img_w) / w # Calculate proportional height
                pdf.image(screenshot_path, x=10, y=10, w=img_w, h=img_h)
        except Exception as img_e:
            logger.error("Error processing image for PDF: %s", img_e)
            pdf.set_font("Arial", "B", 12)
            pdf.text(10, 10, "Error: Could not embed screenshot.")

        pdf.output(pdf_path, "F")
        return True
    except Exception as e:
        logger.error("❌ Failed to move screenshot to evidence PDF: %s", e)
        return False

# ------------------------------------------------------------------
# Classification (infra + visual)
# ------------------------------------------------------------------
def reclassify_label(domain, registrar, host, dns, ocr_text_from_csv):
    """
    Re-classifies the label using heuristics.
    NOTE: This function NO LONGER uses pytesseract. It uses the
    'ocr_text_from_csv' which was generated by EasyOCR.
    """
    reg = str(registrar).lower()
    hst = str(host).lower()
    dns_str = str(dns).lower()
    dom = str(domain).lower()
    ocr_text = str(ocr_text_from_csv).lower() # Use the text from the CSV
    
    ssl_present = "ssl" in dns_str or "tls" in dns_str
    
    # Check if domain or OCR text contains a brand keyword
    brand_hit_domain = any(b in dom for b in BRAND_KEYWORDS)
    brand_hit_ocr = any(b in ocr_text for b in BRAND_KEYWORDS)
    brand_hit = brand_hit_domain or brand_hit_ocr

    if brand_hit:
        if any(r in reg for r in SUSPICIOUS_REGISTRARS) or any(h in hst for h in SUSPICIOUS_HOSTS):
            return "Phishing"
        if (any(r in reg for r in TRUSTED_REGISTRARS) or any(h in hst for h in TRUSTED_HOSTS)) and ssl_present:
            return "Legitimate"
        # If a brand is hit (e.g., "sbi" in URL) but infra is not clearly trusted,
        # it's safer to call it suspected.
        return "Suspected"
        
    if any(r in reg for r in SUSPICIOUS_REGISTRARS) or any(h in hst for h in SUSPICIOUS_HOSTS):
        return "Suspected"
        
    # Default to Legitimate if no other red flags are hit
    return "Legitimate"

# ------------------------------------------------------------------
# Pipeline runner
# ------------------------------------------------------------------
def run_pipeline(holdout_folder, ps02_whitelist_file, limit_whitelisted=None, use_existing_holdout=False):
    logger.info("🚀 Starting pipeline...")
    
    # ROOT_DIR is now defined at the top of the file
    
    # --- This is your new output file ---
    holdout_csv_path = os.path.join(ROOT_DIR, "holdout.csv")

    if not use_existing_holdout or not os.path.exists(holdout_csv_path):
        logger.info("Generating new holdout.csv...")
        holdout_csv_path = generate_shortlisted_csv(
            holdout_folder=holdout_folder,
            ps02_whitelist_file=ps02_whitelist_file,
            limit_whitelisted=limit_whitelisted
        )
        if not os.path.exists(holdout_csv_path):
             logger.error("Failed to generate holdout.csv. Exiting.")
             return
    else:
        logger.info("📂 Using existing holdout file: %s", holdout_csv_path)

    
    ps02_df = pd.read_excel(ps02_whitelist_file)
    if limit_whitelisted is not None:
        ps02_df = ps02_df.head(limit_whitelisted)

    # --- Use the new column name ---
    ps02_df["Legitimate Domains"] = ps02_df["Legitimate Domains"].astype(str).str.strip().str.lower()
    
    df_holdout = pd.read_csv(holdout_csv_path)

    # --- Use the new column name ---
    df_filtered = df_holdout[df_holdout["Legitimate Domains"].isin(ps02_df["Legitimate Domains"])]
    
    # Define a temp file path inside the phishing_pipeline folder
    temp_csv_path = os.path.join(os.path.dirname(__file__), "holdout_temp.csv")
    df_filtered.to_csv(temp_csv_path, index=False, encoding="utf-8")
    
    process_urls(temp_csv_path, FEATURES_CSV)
    df_features = pd.read_csv(FEATURES_CSV)
    df_features = enrich_with_geoip(df_features, ASN_DB_PATH, CITY_DB_PATH)
    df_features.to_csv(FEATURES_ENRICH, index=False, encoding="utf-8")

    # ---------------- Load models ----------------
    model_label, model_source, le_label, source_classes, feature_cols, scaler, imputer = load_models_and_preproc()

    # ---------------- Numeric features ----------------
    # Fill NaN in ocr_text before selection, just in case
    df_features['ocr_text'] = df_features['ocr_text'].fillna("")
    
    X_num = df_features.reindex(columns=feature_cols, fill_value=0)
    X_num_imputed = imputer.transform(X_num)
    X_num_scaled = scaler.transform(X_num_imputed)

    # ---------------- Text TF-IDF features (if you had them) ----------------
    # (Assuming no TF-IDF based on your model_utils.py)
    X_all = X_num_scaled

    # ---------------- Predict labels ----------------
    # We still need to *predict* the label to use it, even if we don't save it.
    y_pred_label = model_label.predict(X_all)
    predicted_labels = le_label.inverse_transform(y_pred_label)
    # df_features["Predicted Label"] = predicted_labels # We no longer save this

    # ---------------- Predict sources ----------------
    y_pred_source = model_source.predict(X_all)
    predicted_sources = [source_classes[i] for i in y_pred_source]
    df_features["Predicted Source"] = predicted_sources

    # ---------------- Adjust sources (heuristic) ----------------
    adjusted_sources = [
        adjust_source(org, dom, ml_source)
        # --- Use the new column names ---
        for org, dom, ml_source in zip(df_features["Cooresponding CSE"], df_features["Legitimate Domains"], df_features["Predicted Source"])
    ]

    # ---------------- Collect WHOIS/DNS and write output ----------------
    records = []
    for idx, row in df_features.iterrows():
        domain_url = row["url"]
        host = urlparse(domain_url).hostname or domain_url
        host = host.split(':')[0]

        # ---
        # --- NEW: Default all variables to "NA" ---
        # ---
        reg_date = "NA"
        registrar = "NA"
        registrant_name = "NA"
        registrant_country = "NA"
        name_servers = "NA"
        ip = "NA"
        dns_records = "NA"
        hosting_isp = "NA"
        hosting_country = "NA"
        
        # --- WHOIS lookup ---
        try:
            w = whois.whois(host)
            if w:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # Only overwrite "NA" if the value is not empty
                if creation_date:
                    reg_date = str(creation_date)
                if w.registrar:
                    registrar = w.registrar
                if w.name or w.org or w.registrant_name:
                    registrant_name = w.name or w.org or w.registrant_name
                if w.country:
                    registrant_country = w.country
                if w.name_servers:
                    ns_list = [str(ns) for ns in w.name_servers]
                    name_servers = ";".join(ns_list)
        except Exception as e:
            logger.debug("WHOIS lookup failed for %s: %s", host, e)

        # --- IP lookup ---
        # Try to get from features file first
        ip_from_features = row.get("ip_address", None)
        if ip_from_features and not pd.isna(ip_from_features):
            ip = str(ip_from_features)
        else:
            try:
                ip_socket = socket.gethostbyname(host)
                if ip_socket:
                    ip = ip_socket
            except Exception as e:
                logger.debug("Socket IP lookup failed for %s: %s", host, e)
        
        # --- DNS lookup ---
        try:
            dns_recs = []
            if host:
                for qtype in ["A", "NS", "MX", "CNAME"]:
                    try:
                        answers = dns.resolver.resolve(host, qtype, lifetime=3)
                        dns_recs.extend([f"{qtype}:{r.to_text()}" for r in answers])
                    except:
                        pass
            if dns_recs:
                dns_records = ";".join(dns_recs)
        except Exception as e:
            logger.debug("DNS lookup failed for %s: %s", host, e)

        # --- GeoIP/ISP lookup (from features file) ---
        isp_from_features = row.get("asn_org", None)
        if isp_from_features and not pd.isna(isp_from_features):
            hosting_isp = str(isp_from_features)
            
        country_from_features = row.get("country", None)
        if country_from_features and not pd.isna(country_from_features):
            hosting_country = str(country_from_features)

        # --- Evidence and screenshot ---
        evidence_path, evidence_name = format_evidence_filename(
            # --- Use the new column name ---
            row["Cooresponding CSE"], domain_url, idx+1, application_id=APPLICATION_ID
        )
        move_screenshot_to_evidence(domain_url, evidence_path)

        # ---
        # --- FINAL FIX: Pass the ocr_text from the CSV to the reclassify function
        # ---
        ocr_text_from_csv = row.get("ocr_text", "")
        classification = reclassify_label(
            domain_url, registrar, hosting_isp, dns_records, ocr_text_from_csv
        )

        detection_date = datetime.now().strftime("%d-%m-%Y")
        detection_time = datetime.now().strftime("%H:%M:%S")

        # ---
        # --- Append the record (all fields will be "NA" if not found) ---
        # ---
        records.append({
            "Application_ID": APPLICATION_ID,
            "Source of detection": adjusted_sources[idx],
            "Identified Phishing/Suspected Domain Name": domain_url,
            # --- Use the new column names ---
            "Corresponding CSE Domain Name": row["Legitimate Domains"],
            "Critical Sector Entity Name": row["Cooresponding CSE"],
            "Phishing/Suspected Domains (i.e. Class Label)": classification,
            # --- "Predicted Label" REMOVED ---
            "Domain Registration Date": reg_date,
            "Registrar Name": registrar,
            "Registrant Name or Registrant Organisation": registrant_name,
            "Registrant Country": registrant_country,
            "Name Servers": name_servers,
            "Hosting IP": ip,
            "Hosting ISP": hosting_isp,
            "Hosting Country": hosting_country,
            "DNS Records (if any)": dns_records,
            "Evidence file name": evidence_name,
            "Date of detection (DD-MM-YYYY)": detection_date,
            "Time of detection (HH-MM-SS)": detection_time,
            "Date of Post (If detection is from Source: social media)": "NA", # Always NA
            # --- "Remarks" Column ADDED ---
            "Remarks": "NA values are due to privacy issues."
        })

    df_out = pd.DataFrame(records)
    # Save to CSV
    df_out.to_csv(FINAL_OUTPUT, index=False, encoding="utf-8")
    logger.info("✅ Final output written to %s", FINAL_OUTPUT)

    # ---------------- Filtering step ----------------
    start = datetime(2025, 10, 1).date()
    end   = datetime(2025, 10, 15).date()

    def parse_date(val):
        if not val or pd.isna(val) or val == "NA":
            return None
        try:
            dt = parser.parse(str(val), fuzzy=True)
            return dt.date()
        except:
            return None

    df_temp = df_out.copy()
    df_temp["_parsed_reg_date"] = df_temp["Domain Registration Date"].apply(parse_date)
    mask = df_temp["_parsed_reg_date"].notna() & df_temp["_parsed_reg_date"].between(start, end)
    df_filtered = df_temp.loc[mask].drop(columns=["_parsed_reg_date"])
    
    # --- Ensure we use the new column order for the filtered file as well ---
    if not df_filtered.empty:
        # Get column order from the *full* output dataframe
        df_filtered = df_filtered[df_out.columns] 

    filtered_path = FINAL_OUTPUT.replace(".csv", "_filtered.csv")
    df_filtered.to_csv(filtered_path, index=False, encoding="utf-8")

    logger.info("✅ Filtered %d domains registered between %s and %s",
                len(df_filtered), start.isoformat(), end.isoformat())
    logger.info("📄 Filtered output written to %s", filtered_path)

    # Remove the temporary holdout_temp.csv file
    try:
        os.remove(temp_csv_path)
        logger.info("🗑 Removed temporary file: %s", temp_csv_path)
    except Exception as e:
        logger.warning("⚠ Could not remove temporary file: %s", e)

    return df_out

# ------------------------------------------------------------------
# Package results
# ------------------------------------------------------------------
def package_results(output_file=FINAL_OUTPUT, zip_path="PS-02_ISS_NLP_Submission.zip"):
    """
    Packages the final output Excel file and the evidence folder into
    a zip file matching the required submission structure.
    """
    import zipfile, os, pathlib
    
    # --- Define the paths for the new zip structure ---
    submission_root_folder = "PS-02_ISS_NLP_Submission"
    documentation_folder_name = "PS-02_ISS_NLP_Documentation"
    excel_file_name = "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"
    
    # Get the evidence folder name from config (e.g., "PS-02_ISS_NLP_Evidences")
    evidence_folder_name = os.path.basename(EVIDENCE_DIR)
    
    # Define the *local* path for the temporary Excel file we will create
    # We'll save it in the same directory as this script (phishing_pipeline/)
    local_excel_path = os.path.join(BASE_DIR, excel_file_name)
    
    # --- Find which CSV to use (filtered or main) ---
    filtered_csv_file = output_file.replace(".csv", "_filtered.csv")
    csv_to_use = None
    
    if os.path.exists(filtered_csv_file):
        try:
            df_check = pd.read_csv(filtered_csv_file)
            if len(df_check) > 0:
                csv_to_use = filtered_csv_file
                logger.info("Using filtered output file: %s", csv_to_use)
            else:
                csv_to_use = output_file
                logger.info("Filtered file is empty. Using main output file: %s", csv_to_use)
        except Exception:
            csv_to_use = output_file
            logger.info("Error checking filtered file. Using main output file: %s", csv_to_use)
    else:
        csv_to_use = output_file
        logger.info("No filtered file found. Using main output file: %s", csv_to_use)

    if not os.path.exists(csv_to_use):
        logger.error("❌ No output CSV file found to package: %s", csv_to_use)
        return

    # --- Convert the final CSV to the new Excel file ---
    try:
        df_final_output = pd.read_csv(csv_to_use)
        
        # --- NEW: Fill any remaining NaNs with "NA" before saving to Excel ---
        # This is a final safeguard.
        df_final_output.fillna("NA", inplace=True)
        
        df_final_output.to_excel(local_excel_path, index=False)
        logger.info("✅ Converted final output CSV to %s", excel_file_name)
    except Exception as e:
        logger.error("❌ Failed to create Excel file: %s", e)
        return

    # --- Create the new ZIP file with the correct structure ---
    files_added_count = 0
    # Note: zip_path is now created in the *root* directory
    zip_path_full = os.path.join(ROOT_DIR, zip_path) 
    
    with zipfile.ZipFile(zip_path_full, 'w', zipfile.ZIP_DEFLATED) as zipf:
        
        # 1) Add the Evidence folder and all its contents
        if os.path.exists(EVIDENCE_DIR):
            for root, _, files in os.walk(EVIDENCE_DIR):
                for file in files:
                    filepath = os.path.join(root, file)
                    # Arcname places it inside the new structure
                    arcname = os.path.join(submission_root_folder, evidence_folder_name, file)
                    zipf.write(filepath, arcname)
                    files_added_count += 1
            logger.info("Added %d evidence files.", files_added_count)
        else:
            logger.warning("Evidence directory not found. Skipping: %s", EVIDENCE_DIR)

        # 2) Add the new Excel file to the Documentation folder
        if os.path.exists(local_excel_path):
            #arcname = os.path.join(submission_root_folder, documentation_folder_name, excel_file_name)
            arcname = os.path.join(submission_root_folder, excel_file_name)
            zipf.write(local_excel_path, arcname)
            files_added_count += 1
            logger.info("Added final Excel sheet.")
        else:
            logger.error("❌ Could not find temporary Excel file to add: %s", local_excel_path)
            
    # --- Clean up the temporary Excel file we created ---
    try:
        os.remove(local_excel_path)
        logger.info("🗑 Removed temporary Excel file: %s", local_excel_path)
    except Exception as e:
        logger.warning("⚠ Could not remove temporary Excel file: %s", e)

    logger.info("📦 Packaged results into %s. Files included: %d", zip_path_full, files_added_count)

    # --- Call the existing cleanup function ---
    # This will remove all the intermediate .csv, /screens, and /evidence folders
    try:
        cleanup_generated_artifacts(zip_path=zip_path_full)
    except Exception as e:
        logger.warning("⚠ Cleanup after packaging failed: %s", e)

    return zip_path_full


def cleanup_generated_artifacts(root_dir=None, zip_path="PS-02_ISS_NLP_Submission.zip"):
    """
    Cleans up all intermediate files (CSVs, screenshots, evidence)
    after the final zip has been created.
    """
    import os, shutil, pathlib
    
    if root_dir is None:
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")) # project root
    logger.info("🧹 Cleaning generated artifacts in %s (preserving code & models)...", root_dir)

    project_root = pathlib.Path(root_dir)
    zip_path_abs = pathlib.Path(zip_path).resolve() # Use absolute path for comparison

    # List of files/folders to delete
    # Note: We do *not* delete *.xlsx files, only the temporary one.
    patterns_to_delete = [
        "*.csv", # Deletes holdout.csv, features.csv, etc. from pipeline and root
    ]
    
    folders_to_delete = [
        SCREENS_DIR,  # The screenshot folder
        EVIDENCE_DIR, # The evidence folder
    ]

    # Delete matching files in root and phishing_pipeline folder
    for pattern in patterns_to_delete:
        for p in project_root.glob(pattern):
            if p.is_file() and p.resolve() != zip_path_abs:
                try:
                    p.unlink()
                    logger.info("🗑 Deleted file: %s", p)
                except Exception as e:
                    logger.debug("Could not delete file: %s (%s)", p, e)
        
        for p in (project_root / "phishing_pipeline").glob(pattern):
             if p.is_file() and p.resolve() != zip_path_abs:
                try:
                    p.unlink()
                    logger.info("🗑 Deleted file: %s", p)
                except Exception as e:
                    logger.debug("Could not delete file: %s (%s)", p, e)

    # Delete directories
    for dir_path_str in folders_to_delete:
        dir_path = pathlib.Path(dir_path_str)
            
        if dir_path.exists() and dir_path.is_dir():
            try:
                shutil.rmtree(dir_path)
                logger.info("🗑 Removed folder: %s", dir_path)
            except Exception as e:
                logger.warning("Could not remove folder: %s (%s)", dir_path, e)

    logger.info("✅ Cleanup complete. Kept code, models, and final zip: %s", zip_path)


# -------------------- Main entry point --------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run the phishing pipeline (pipeline.py).")
    parser.add_argument("holdout_folder",
                        help="Folder where CSVs will be read/written (pass '.' for current dir)")
    parser.add_argument("ps02_whitelist_file",
                        help="Path to PS-02 whitelist Excel file (e.g. PS-02_hold-out_Set1_Legitimate_Domains_for_10_CSEs.xlsx)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Optional: limit how many whitelisted rows to process (for testing)")
    parser.add_argument("--use-existing-holdout", action="store_true",
                        help="If set and holdout.csv exists, reuse it instead of regenerating.")
    
    # ---
    # --- FIX 2: Corrected 'addD-argument' to 'add_argument'
    # ---
    parser.add_argument("--package-results", action="store_true",
                        help="If set, package filtered results + evidence into a zip after pipeline finishes.")
    # --- (End of Fix 2) ---
    
    args = parser.parse_args()

    # Run the pipeline with provided args
    out = run_pipeline(args.holdout_folder, args.ps02_whitelist_file,
                       limit_whitelisted=args.limit, use_existing_holdout=args.use_existing_holdout)

    # Optionally package results
    if args.package_results:
        zip_path = package_results()
        logger.info("Packaged results into %s", zip_path)