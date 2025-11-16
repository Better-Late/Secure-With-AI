# 🔒 Secure with AI

Comprehensive security analysis platform powered by artificial intelligence that helps you evaluate the security and trustworthiness of software products.

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.51.0+-red.svg)](https://streamlit.io)

## 🌟 Features

- **🔍 Multi-Factor Security Analysis**: Combines multiple data sources to provide a comprehensive security score (0-100)
- **🛡️ CVE Vulnerability Detection**: Automatically searches for and analyzes known vulnerabilities
- **🦠 VirusTotal Integration**: Checks file hashes against 90+ antivirus engines
- **📊 Popularity Scoring**: Uses Google Trends to gauge community interest and adoption
- **⚖️ License Detection**: Identifies open-source and proprietary licenses with compliance information
- **🏛️ GDPR Compliance Tracking**: Checks for GDPR enforcement actions and fines
- **💥 Data Breach History**: Searches historical breach database for security incidents
- **🔄 Alternative Suggestions**: Recommends similar software products
- **📁 Batch Analysis**: CSV upload support for analyzing multiple products at once
- **💾 Smart Caching**: Results are cached to improve performance on repeated queries

## 📸 Screenshots

The application provides an intuitive web interface for security analysis with:
- Real-time security scoring with color-coded indicators
- Detailed breakdown of all security factors
- Interactive expandable summaries
- Batch processing capabilities

## 🚀 Getting Started

### Prerequisites

- Python 3.13 or higher
- API keys for:
  - Google Gemini AI
  - VirusTotal (optional, for hash analysis)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Better-Late/Secure-With-AI.git
   cd Secure-With-AI
   ```

2. **Install dependencies with uv**

3. **Set up environment variables**
   
   Create a `.env` file in the project root:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   LOCAL=true (for local development)
   ```

4. **Run the application**
   ```bash
   streamlit run app.py
   ```

5. **Access the web interface**
   
   Open your browser and navigate to `http://localhost:8501`

## 🎯 Usage

### Single Product Analysis

1. Enter the **Company Name** (e.g., "Microsoft")
2. Enter the **Product Name** (e.g., "Visual Studio Code")
3. (Optional) Enter a **File Hash** for VirusTotal analysis
4. Click **Analyze** to generate the security report

### Batch Analysis

1. Prepare a CSV file with the following columns:
   ```
   company_name,product_name,hash
   Microsoft,Visual Studio Code,abc123...
   Mozilla,Firefox,def456...
   ```

2. Click **Upload CSV** in the sidebar
3. Click **Load CSV Data**
4. Click **Analyze All** to process all entries at once

### Understanding the Trust Score

The **Trust Score** (0-100) is calculated based on:

- **Popularity Score** (via Google Trends) - 66.7% weight in reputation
- **CVE Vulnerability Score** - 33.3% weight in reputation
  - Unsolved CVEs: ×1.5 penalty
  - Unknown status: ×1.2 penalty
  - Solved CVEs: ×1.0 (no penalty)
- **VirusTotal Score** (if hash provided) - 50% of final score when available
- **GDPR Penalty** - Up to 10 points deducted for enforcement actions
- **Data Breach Penalty** - Up to 10 points deducted for breach history

**Special Cases:**
- Malware-flagged software receives a fixed score of **10/100**
- Products with no information receive a score of **0/100**

Click the **Score Details** button in the UI for the full mathematical breakdown.

## 🏗️ Architecture

### Core Components

- **`app.py`**: Streamlit web application frontend
- **`security_analysis.py`**: Main analysis orchestration and scoring logic
- **`entity_resolution.py`**: Identifies and resolves software entities
- **`search_vulnerabilities.py`**: CVE and vulnerability database search
- **`virustotal.py`**: VirusTotal API integration
- **`popularity.py`**: Google Trends data collection
- **`licensing/`**: License detection and compliance checking
  - GitHub repository license detection
  - Website terms/pricing scraping
  - AI-powered license assessment
- **`gdpr.py`**: GDPR enforcement action lookup
- **`alternatives.py`**: Alternative software recommendations
- **`score.py`**: Trust score calculation algorithms

### Data Flow

```
User Input → Entity Resolution → Parallel Analysis:
                                  ├─ CVE Search
                                  ├─ VirusTotal
                                  ├─ Google Trends
                                  ├─ License Detection
                                  ├─ GDPR Lookup
                                  └─ Breach Search
                                       ↓
                                  Score Calculation
                                       ↓
                                  Report Generation
```

## 🐳 Docker Deployment

Build and run with Docker:

```bash
docker build -t secure-with-ai .
docker run -p 8501:8501 --env-file .env secure-with-ai
```

## 📊 Data Sources

- **CVE Database**: National Vulnerability Database (NVD)
- **VirusTotal**: 90+ antivirus engine results
- **Google Trends**: Search interest over time
- **GDPR Tracker**: European data protection enforcement database
- **Breach Database**: Historical data breach records (`breaches.csv`)
- **GitHub**: Open-source license information
- **AI Analysis**: Google Gemini for intelligent license assessment

## 🧪 Testing

Run the test suite:

```bash
pytest tests/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer

This tool provides automated security analysis based on publicly available data. Results should be used as part of a comprehensive security assessment and not as the sole basis for security decisions. Always verify critical findings manually.

## 🙏 Acknowledgments

- Built for hackathon participation
- Powered by Google Gemini AI
- Integrates VirusTotal API
- Uses Streamlit for the web interface

## 📧 Contact

Project Link: [https://github.com/Better-Late/Secure-With-AI](https://github.com/Better-Late/Secure-With-AI)

---

**Made with no sleep by the Better-late-than-never team**
