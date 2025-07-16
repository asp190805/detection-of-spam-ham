
import streamlit as st
import joblib
import re
import pandas as pd
import os
import mimetypes
import hashlib

# === Load saved components ===
pipeline = joblib.load("spam_classifier.joblib")
vectorizer = joblib.load("vectorizer.joblib")
scaler = joblib.load("scaler.joblib")
regression = joblib.load("regression.joblib")

# === Utility functions ===

def check_subject_spam(subject):
    spam_keywords = ['free', 'win', 'prize', 'congratulations', 'urgent', 'offer']
    return int(any(word in subject.lower() for word in spam_keywords))

def extract_url_features(text):
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account']
    encoded_char_pattern = re.compile(r'%[0-9a-fA-F]{2}')
    ip_pattern = re.compile(r'(http|https):\/\/(?:\d{1,3}\.){3}\d{1,3}')
    suspicious_domain_pattern = re.compile(r'\.com[^/\.]{2,}')
    urls = re.findall(r'http[s]?://[^\s]+', text)
    combined_url = ' '.join(urls).lower()
    return {
        'has_suspicious_word': int(any(word in combined_url for word in suspicious_keywords)),
        'has_encoded_chars': int(bool(encoded_char_pattern.search(combined_url))),
        'has_ip': int(bool(ip_pattern.search(combined_url))),
        'url_length': len(combined_url),
        'has_suspicious_domain': int(bool(suspicious_domain_pattern.search(combined_url)))
    }

def extract_body_features(text):
    spammy_keywords = ['free', 'winner', 'guaranteed', 'risk-free', 'urgent',
                       'congratulations', 'exclusive', 'act now', 'bonus', 'limited time']
    cleaned = re.sub(r'http\S+', '', text)
    text_lower = cleaned.lower()
    total_chars = len(cleaned)
    upper_chars = sum(1 for c in cleaned if c.isupper())
    return {
        'has_spammy_words': int(any(word in text_lower for word in spammy_keywords)),
        'num_exclamations': text.count('!'),
        'percent_uppercase': upper_chars / total_chars if total_chars > 0 else 0,
        'has_suspicious_symbols': int(bool(re.search(r'[^a-zA-Z0-9\s]{3,}', cleaned))),
        'has_spaced_letters': int(bool(re.search(r'(\w\s){2,}\w', cleaned)))
    }

def extract_attachment_features(uploaded_file):
    EXECUTABLE_EXT = {'.exe', '.bat', '.cmd', '.scr', '.com', '.js', '.vbs'}
    ARCHIVE_EXT = {'.zip', '.rar', '.7z', '.gz', '.tar'}
    MACRO_OFFICE = {'.doc', '.docm', '.xls', '.xlsm', '.pptm'}
    SUSPICIOUS_NAME_PATTERN = re.compile(r'(password|invoice|urgent|free|win)', re.I)

    if uploaded_file is None:
        return {
            'has_executable': 0, 'has_archive': 0, 'has_office_macro': 0,
            'suspicious_filename': 0, 'suspicious_mime': 0
        }

    fname = uploaded_file.name
    ext = os.path.splitext(fname)[1].lower()

    features = {
        'has_executable': int(ext in EXECUTABLE_EXT),
        'has_archive': int(ext in ARCHIVE_EXT),
        'has_office_macro': int(ext in MACRO_OFFICE),
        'suspicious_filename': int(bool(SUSPICIOUS_NAME_PATTERN.search(fname))),
        'suspicious_mime': 0
    }

    mimetype, _ = mimetypes.guess_type(fname)
    if mimetype and mimetype.startswith(("application/x-dosexec", "text/x-script")):
        features['suspicious_mime'] = 1

    return features

def detect_spam_sources(row):
    reasons = []
    if row['subject_flag']: reasons.append('subject')
    if row['has_spammy_words'] or row['has_suspicious_symbols'] or row['has_spaced_letters'] or row['percent_uppercase'] > 0.3:
        reasons.append('body')
    if row['has_suspicious_word'] or row['has_encoded_chars'] or row['has_ip'] or row['url_length'] > 70 or row['has_suspicious_domain']:
        reasons.append('url')
    if row['has_executable'] or row['has_archive'] or row['has_office_macro'] or row['suspicious_filename'] or row['suspicious_mime']:
        reasons.append('attachment')
    return ", ".join(reasons) if reasons else "none"

# === Streamlit UI ===
st.title("📧 Email Spam Detector")

subject = st.text_input("Subject")
body = st.text_area("Body")
uploaded_file = st.file_uploader("Attachment (optional)", type=["pdf", "docx", "exe", "xlsx", "zip"])

if st.button("Detect Spam"):
    subject_flag = check_subject_spam(subject)
    url_feats = extract_url_features(body)
    body_feats = extract_body_features(body)
    attach_feats = extract_attachment_features(uploaded_file)

    all_feats = {
        'subject_flag': subject_flag,
        **url_feats,
        **body_feats,
        **attach_feats
    }

    is_spam = (
        subject_flag == 1 or
        all_feats['has_suspicious_word'] or all_feats['has_encoded_chars'] or all_feats['has_ip'] or
        all_feats['url_length'] > 70 or all_feats['has_suspicious_domain'] or
        all_feats['has_spammy_words'] or all_feats['has_suspicious_symbols'] or all_feats['has_spaced_letters'] or
        all_feats['percent_uppercase'] > 0.3 or
        all_feats['has_executable'] or all_feats['has_archive'] or all_feats['has_office_macro'] or
        all_feats['suspicious_filename'] or all_feats['suspicious_mime']
    )

    verdict = "spam" if is_spam else "ham"
    spam_sources = detect_spam_sources(all_feats)

    st.markdown(f"### 🔍 Verdict: **{verdict.upper()}**")
    st.markdown(f"**Detected in**: {spam_sources}")
