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
    st.session_state.num_fields = 3

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
        return "green"
    elif score >= 50:
        return "orange"
    else:
        return "red"


def render_header():
    """Render the page header and title."""
    st.title("🔒 Security Analysis Tool")
    st.markdown("Enter company and program details to analyze and click **Analyze** to get security summaries.")


def render_analyze_all_button():
    """Render the Analyze All button and handle its logic."""
    col_left, col_center, col_right = st.columns([2, 1, 2])
    with col_center:
        if st.button("🔍 Analyze All", use_container_width=True, type="primary"):
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
    st.markdown("""
    ## 📘 Formulas

    - Add any detailed documentation here  
    - kadnjasda
    """)


def render_sidebar():
    """Render the sidebar with settings and controls."""
    with st.sidebar:
        st.header("Settings")
        
        # CSV Upload
        st.subheader("📁 Upload CSV")
        uploaded_file = st.file_uploader(
            "Upload a CSV file with company, product, and hash data",
            type=['csv'],
            help="CSV should have columns: company_name, product_name, hash"
        )
        
        if uploaded_file is not None:
            if st.button("Load CSV Data", type="primary"):
                entries = parse_csv(uploaded_file)
                if entries:
                    st.session_state.num_fields = len(entries)
                    st.session_state.field_data = {i: entry for i, entry in enumerate(entries)}
                    st.session_state.search_results = {}  # Clear previous results
                    st.success(f"Loaded {len(entries)} entries from CSV!")
                    st.rerun()
                else:
                    st.warning("No valid entries found in CSV")
        
        st.divider()
        
        if st.button("Clear All Results", type="secondary"):
            st.session_state.search_results = {}
            st.rerun()
        
        st.divider()
        st.markdown("""
        ### How to use
        1. **Option A**: Enter company, product names, and hash manually
        2. **Option B**: Upload a CSV file with columns: `company_name`, `product_name`, `hash`
        3. Click **Analyze All** to analyze all entries at once, or click individual Analyze buttons
        4. View the security score and summary
        5. Click the + button to add more fields
        """)


def render_results(i: int, stored_company: str, stored_product: str, stored_hash: str, result: Dict):
    """Render the results section for a search field."""
    hash_display = f" (Hash: {stored_hash})" if stored_hash else ""
    st.markdown(f"**Results for:** *{stored_company} - {stored_product}{hash_display}*")
    
    # Display security score with colored indicator
    score = result['score']
    score_color = get_score_color(score)
    
    col_score, col_summary = st.columns([1, 4])
    
    with col_score:
        st.markdown(f"""
        <div style="text-align: center; padding: 20px; background-color: {score_color}; 
                    border-radius: 10px; color: white;">
            <h1 style="margin: 0; color: white;">{score}</h1>
            <p style="margin: 0; color: white;">Security Score</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("ℹ️ What does this score mean?", key=f"score_info_btn_{score}", width="stretch"):
            score_dialog()

    with col_summary:
        # Display summary in an expander
        with st.expander("📋 View Full Summary", expanded=True):
            st.markdown(result['summary'])


def render_search_field(i: int):
    """Render a single search field with input boxes and analyze button."""
    with st.container():
        # Compact separator instead of full divider
        st.markdown(f"<div style='margin: 5px 0; border-bottom: 1px solid #ddd;'></div>", unsafe_allow_html=True)
        
        # Get pre-populated data if it exists
        company_default = st.session_state.field_data.get(i, {}).get('company_name', '')
        product_default = st.session_state.field_data.get(i, {}).get('product_name', '')
        hash_default = st.session_state.field_data.get(i, {}).get('hash', '')
        
        col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
        
        with col1:
            company_name = st.text_input(
                f"Company Name {i+1}",
                key=f"company_{i}",
                value=company_default,
                placeholder="Enter company name..."
            )
        
        with col2:
            product_name = st.text_input(
                f"Product Name {i+1}",
                key=f"product_{i}",
                value=product_default,
                placeholder="Enter product name..."
            )
        
        with col3:
            hash_value = st.text_input(
                f"Hash {i+1}",
                key=f"hash_{i}",
                value=hash_default,
                placeholder="Enter hash..."
            )
        
        with col4:
            st.markdown("<br>", unsafe_allow_html=True)  # Align button with input
            analyze_clicked = st.button("🔍 Analyze", key=f"analyze_{i}")
        
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
    st.markdown("---")  # Compact separator
    col1, col2, col3 = st.columns([2, 1, 2])
    with col2:
        if st.button("➕ Search More", use_container_width=True, type="secondary"):
            st.session_state.num_fields += 1
            st.rerun()


def main():
    st.set_page_config(
        page_title="Security Analysis Tool",
        page_icon="🔒",
        layout="wide"
    )
    
    render_header()
    render_analyze_all_button()
    render_sidebar()
    render_search_fields()
    render_add_field_button()


if __name__ == "__main__":
    main()
