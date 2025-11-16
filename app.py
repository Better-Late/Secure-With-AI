import streamlit as st
from typing import Dict, Optional, List
import csv
import io
import asyncio
from security_analysis import analysis

# Initialize session state for storing search results
if 'search_results' not in st.session_state:
    st.session_state.search_results = {}

if 'num_fields' not in st.session_state:
    st.session_state.num_fields = 1

if 'field_data' not in st.session_state:
    st.session_state.field_data = {}

def parse_csv(uploaded_file) -> List[Dict[str, str]]:
    """
    Parse CSV file and return list of entries with company_name, product_name, and hash.
    Expected CSV format: company_name,product_name,hash
    """
    entries = []
    try:
        content = uploaded_file.read().decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(content))
        
        for row in csv_reader:
            # Handle different possible column names
            company = row.get('company_name') or row.get('company') or row.get('Company Name') or row.get('Company') or ''
            product = row.get('product_name') or row.get('product') or row.get('Product Name') or row.get('Product') or ''
            hash_value = row.get('hash') or row.get('Hash') or row.get('hash_value') or row.get('Hash Value') or ''
            
            if company or product or hash_value:  # Add if at least one field has data
                entries.append({
                    'company_name': company.strip(),
                    'product_name': product.strip(),
                    'hash': hash_value.strip()
                })
    except Exception as e:
        st.error(f"Error parsing CSV: {str(e)}")
    
    return entries


def get_score_color(score: int) -> str:
    """Return color based on security score."""
    if score >= 80:
        return "#10b981"  # Green
    elif score >= 50:
        return "#f59e0b"  # Orange
    else:
        return "#ef4444"  # Red


def apply_custom_css():
    """Apply minimal custom CSS styling - rely mainly on Streamlit theme."""
    st.markdown("""
    <style>
        /* Input fields focus */
        .stTextInput input:focus {
            border-color: #8b5cf6 !important;
            box-shadow: 0 0 0 1px #8b5cf6 !important;
        }
        
        /* Buttons styling */
        .stButton button {
            border-radius: 8px !important;
            font-weight: 600 !important;
            transition: all 0.3s ease !important;
        }
        
        .stButton button[kind="primary"]:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4) !important;
        }
        
        .stButton button[kind="secondary"]:hover {
            transform: translateY(-2px);
        }
        
        /* Score card enhancement */
        .score-card {
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .score-card:hover {
            transform: translateY(-4px);
        }
    </style>
    """, unsafe_allow_html=True)


def render_header():
    """Render the page header and title."""
    st.markdown("""
    <div style="text-align: center; padding: 2rem 0;">
        <h1 style="font-size: 3.5rem; margin-bottom: 0.5rem; color: #8b5cf6;">
            Secure with AI
        </h1>
        <p style="font-size: 1.2rem; margin-top: 0;">
            Comprehensive security analysis powered by artificial intelligence
        </p>
        <p style="font-size: 0.95rem; max-width: 600px; margin: 1rem auto;">
            Enter company and product details to analyze and click <strong>Analyze</strong> to get security summaries
        </p>
    </div>
    """, unsafe_allow_html=True)


def render_analyze_all_button():
    """Render the Analyze All button and handle its logic."""
    # Only show if there are more than 2 rows
    if st.session_state.num_fields <= 2:
        return
    
    col_left, col_center, col_right = st.columns([2, 1, 2])
    with col_center:
        if st.button("Analyze All", use_container_width=True, type="primary"):
            # Collect all fields that have data
            tasks_to_run = []
            for i in range(st.session_state.num_fields):
                # Get company, product, and hash values from session state or field_data
                company = st.session_state.get(f"company_{i}", "") or st.session_state.field_data.get(i, {}).get('company_name', '')
                product = st.session_state.get(f"product_{i}", "") or st.session_state.field_data.get(i, {}).get('product_name', '')
                hash_value = st.session_state.get(f"hash_{i}", "") or st.session_state.field_data.get(i, {}).get('hash', '')

                if company.strip() or product.strip() or hash_value.strip():
                    tasks_to_run.append((i, company, product, hash_value))

            # Run all analyses concurrently
            if tasks_to_run:
                async def run_all_analyses():
                    async def analyze_single(idx, comp, prod, hash_val):
                        result = await analysis(comp, prod, hash_val)
                        return (idx, comp, prod, hash_val, result)

                    return await asyncio.gather(*[analyze_single(i, c, p, h) for i, c, p, h in tasks_to_run])

                results = asyncio.run(run_all_analyses())

                # Store all results
                for idx, company, product, hash_value, result in results:
                    st.session_state.search_results[idx] = {
                        'company_name': company,
                        'product_name': product,
                        'hash': hash_value,
                        'result': result
                    }
            st.rerun()

    st.markdown("---")  # Compact separator




@st.dialog("Score Calculation")
def score_dialog():
    st.markdown(r"""
# 🔒 Trust Score Calculation 

Our **Trust Score** summarizes several security and reputation signals into a single value between **0 and 100**. Below is how each component works, written in a clear and human-readable format.

---

## 📈 1. Popularity Score (Google Trends)

* We pull **12 months of Google Trends data** to measure public interest.
* This value is **multiplied by 1.5** to emphasize recent popularity and capped at **100**.
* Why it matters:
  Higher interest → more community attention → usually better security practices.

---

## 🛡️ 2. CVE / Vulnerability Score

We look at known CVEs and their CVSS severity ratings. Each CVE gets a multiplier depending on its status:

* **Unsolved CVEs:** × **1.5** penalty  
* **Unknown status:** × **1.2** penalty  
* **Solved CVEs:** × **1.0** (no penalty)

The combined risk total is then converted into a score:

$$
\text{CVE Score} = \left(1 - \frac{\text{total\_risk}}{\text{total\_risk} + 40}\right) \times 100
$$

This method prevents the score from tanking too quickly and ensures that **0 CVEs = perfect 100**.

---

## ⚖️ 3. Reputation Score (Popularity + CVE)

We blend the two earlier scores:

* **66.7%** Popularity  
* **33.3%** CVE Score  

This weighting reflects that **community scrutiny matters more than raw vulnerability count**.

---

## 🧪 4. VirusTotal Score (only if a file hash is provided)

If the user provides a hash, we check it across 90+ antivirus engines.

The score is:

$$
\text{VirusTotal Score} = \left(1 - \frac{\text{malicious} + \text{suspicious}}{\text{total\_scans}}\right) \times 100
$$

* This directly measures malware detection rates.
* If the file is flagged as malware, we **skip all calculations** and immediately return a **10/100** to indicate severe risk.

---

## 🧮 5. Final Score Calculation

* **Without a file hash:**  
  Final Score = **Reputation Score**

* **With a file hash:**  
  Final Score = **50% Reputation + 50% VirusTotal**

* **GDPR Penalty:**  
  Up to **10 points** may be subtracted if the company has recorded enforcement actions in the GDPR Enforcement Tracker.

Finally:

* The score is **clamped between 0 and 100**  
* Rounded to **two decimals**  
* Returned with a **detailed breakdown** of all components

---

## ⚠️ 6. Special Case: Malware-Flagged Software

If VirusTotal marks the file as malware:

* Final Score = **10/100**
* No other calculations are performed

---
"""
)


def render_sidebar():
    """Render the sidebar with settings and controls."""
    with st.sidebar:
        st.markdown("""
        <h2 style="color: #8b8b8b; margin-bottom: 1.5rem; font-size: 1.3rem;">
            Settings
        </h2>
        """, unsafe_allow_html=True)
        
        # CSV Upload
        st.markdown("""
        <div style="padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
            <p style="color: #8b8b8b; font-weight: 600; margin-bottom: 0.5rem; font-size: 0.95rem;">Upload CSV</p>
        </div>
        """, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Upload CSV file",
            type=['csv'],
            help="CSV should have columns: company_name, product_name, hash",
            label_visibility="collapsed"
        )
        
        if uploaded_file is not None:
            if st.button("Load CSV Data", type="primary", use_container_width=True):
                entries = parse_csv(uploaded_file)
                if entries:
                    st.session_state.num_fields = len(entries)
                    st.session_state.field_data = {i: entry for i, entry in enumerate(entries)}
                    st.session_state.search_results = {}  # Clear previous results
                    st.success(f"Loaded {len(entries)} entries!")
                    st.rerun()
                else:
                    st.warning("No valid entries found")
        
        st.markdown("<div style='margin: 1.5rem 0; height: 1px;'></div>", unsafe_allow_html=True)
        
        if st.button("Clear All Results", type="secondary", use_container_width=True):
            st.session_state.search_results = {}
            st.rerun()
        
        st.markdown("<div style='margin: 1.5rem 0; height: 1px;'></div>", unsafe_allow_html=True)
        
        st.markdown("""
        <div style="padding: 1.2rem; border-radius: 8px;">
            <p style="color: #8b8b8b; font-weight: 600; margin-bottom: 1rem; font-size: 1.05rem;">
                How to Use
            </p>
            <div style="color: #a0a0a0; font-size: 0.85rem; line-height: 1.8;">
                <p style="margin-bottom: 0.5rem;"><strong style="color: #b0b0b0;">Option A:</strong> Manual Entry</p>
                <p style="margin-left: 1rem; margin-top: 0.3rem; margin-bottom: 1rem;">Enter company, product names, and hash manually in the fields below.</p>   
                <p style="margin-bottom: 0.5rem;"><strong style="color: #b0b0b0;">Option B:</strong> CSV Upload</p>
                <p style="margin-left: 1rem; margin-top: 0.3rem; margin-bottom: 0.5rem;">Upload a CSV with columns:</p>
                <p style="margin-left: 2rem; font-family: monospace; font-size: 0.8rem; color: #c0c0c0;">company_name, product_name, hash</p>
                <p style="margin-top: 1rem; margin-bottom: 0.5rem;"><strong style="color: #b0b0b0;">Analysis:</strong></p>
                <ul style="margin-left: 1.5rem; margin-top: 0.3rem; padding-left: 0.5rem;">
                    <li>Click <strong>Analyze All</strong> for batch processing (3+ rows)</li>
                    <li>Click individual <strong>Analyze</strong> buttons for single entries</li>
                </ul>
                <p style="margin-top: 1rem; margin-bottom: 0.5rem;"><strong style="color: #b0b0b0;">Tips:</strong></p>
                <ul style="margin-left: 1.5rem; margin-top: 0.3rem; padding-left: 0.5rem;">
                    <li>View detailed security scores and summaries</li>
                    <li>Add more fields with the + button</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)


def render_results(i: int, stored_company: str, stored_product: str, stored_hash: str, result: Dict):
    """Render the results section for a search field."""
    hash_display = f" (Hash: {stored_hash[:16]}...)" if stored_hash else ""
    st.markdown(f"""
    <div style="padding: 1rem; border-radius: 12px; margin: 1rem 0; 
                border: 1px solid #3a3a4e;">
        <p style="color: #a0a0b0; margin: 0; font-size: 0.9rem;">
            <strong style="color: #8b5cf6;">Results for:</strong> 
            <em style="color: #d0d0d0;">{stored_company} - {stored_product}{hash_display}</em>
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Display security score with colored indicator
    score = result['score']
    score_color = get_score_color(score)
    breakdown = result.get("score_breakdown", {})
    col_score, col_summary = st.columns([1, 4])
    
    with col_score:
        breakdown_items = ""
        for name, value in breakdown.items():
            breakdown_items += (
                f"<div style='font-size: 11px; margin-top: 6px; color: rgba(255,255,255,0.8);'>"
                f"<strong>{name}:</strong> {value}"
                f"</div>"
            )

        html = (
            f"<div class='score-card' style='background: {score_color}; "
            f"border-radius: 16px; padding: 28px; text-align: center; "
            f"box-shadow: 0 8px 24px rgba(0,0,0,0.3);'>"
            f"<h1 style='margin: 0; color: white; font-size: 3.5rem; font-weight: 700;'>{score:.0f}</h1>"
            f"<p style='margin: 8px 0 0 0; color: white; font-size: 0.9rem; font-weight: 600; letter-spacing: 1px;'>SECURITY SCORE</p>"
            f"<div style='margin-top: 16px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.2);'>{breakdown_items}</div>"
            f"</div>"
        )

        st.markdown(html, unsafe_allow_html=True)

        if st.button("Score Details", key=f"score_info_btn_{i}", use_container_width=True):
            score_dialog()

    with col_summary:
        # Display summary in an expander
        with st.expander("View Full Summary", expanded=True):
            st.markdown(result['summary'], unsafe_allow_html=True)


def render_search_field(i: int):
    """Render a single search field with input boxes and analyze button."""
    with st.container():
        # Modern separator
        st.markdown(f"""
        <div style='margin: 20px 0; height: 1px; background: #3a3a4e;'>
        </div>
        """, unsafe_allow_html=True)
        
        # Get pre-populated data if it exists
        company_default = st.session_state.field_data.get(i, {}).get('company_name', '')
        product_default = st.session_state.field_data.get(i, {}).get('product_name', '')
        hash_default = st.session_state.field_data.get(i, {}).get('hash', '')
        
        col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
        
        with col1:
            company_name = st.text_input(
                f"Company Name",
                key=f"company_{i}",
                value=company_default,
                placeholder="Enter company name...",
                label_visibility="visible"
            )
        
        with col2:
            product_name = st.text_input(
                f"Product Name",
                key=f"product_{i}",
                value=product_default,
                placeholder="Enter product name...",
                label_visibility="visible"
            )
        
        with col3:
            hash_value = st.text_input(
                f"Hash",
                key=f"hash_{i}",
                value=hash_default,
                placeholder="Enter hash (optional)...",
                label_visibility="visible"
            )
        
        with col4:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)  # Align button with input
            analyze_clicked = st.button("Analyze", key=f"analyze_{i}", type="primary", use_container_width=True)
        
        # Perform analysis when button is clicked
        if analyze_clicked and (company_name.strip() or product_name.strip() or hash_value.strip()):
            print(f'Analysis started for: {company_name} - {product_name} - {hash_value}')
            with st.spinner(f"Analyzing '{company_name} - {product_name}'..."):
                # Call your security analysis function here
                result = asyncio.run(analysis(company_name, product_name, hash_value))
                st.session_state.search_results[i] = {
                    'company_name': company_name,
                    'product_name': product_name,
                    'hash': hash_value,
                    'result': result
                }
        
        # Display results if they exist for this field
        if i in st.session_state.search_results:
            stored_company = st.session_state.search_results[i]['company_name']
            stored_product = st.session_state.search_results[i]['product_name']
            stored_hash = st.session_state.search_results[i].get('hash', '')
            result = st.session_state.search_results[i]['result']
            render_results(i, stored_company, stored_product, stored_hash, result)


def render_search_fields():
    """Render all search fields."""
    for i in range(st.session_state.num_fields):
        render_search_field(i)


def render_add_field_button():
    """Render the add field button at the bottom."""
    st.markdown("""
    <div style='margin: 30px 0; height: 1px; background: #3a3a4e;'>
    </div>
    """, unsafe_allow_html=True)    
    col1, col2, col3 = st.columns([2, 1, 2])
    with col2:
        if st.button("Add More Fields", use_container_width=True, type="secondary"):
            st.session_state.num_fields += 1
            st.rerun()


def main():
    st.set_page_config(
        page_title="Secure with AI",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Apply custom styling
    apply_custom_css()
    
    render_header()
    render_analyze_all_button()
    render_sidebar()
    render_search_fields()
    render_add_field_button()


if __name__ == "__main__":
    main()
