#!/bin/bash
set -e

# Fail if secrets aren't set
if [ -z "$BASIC_AUTH_USER" ] || [ -z "$BASIC_AUTH_PASS" ] || [ -z "$GEMINI_API_KEY" ] || [ -z "$VIRUSTOTAL_API_KEY" ]; then
  echo "[ERROR] Missing required secrets."
  exit 1
fi

# Create .htpasswd file for nginx
htpasswd -bc /etc/nginx/.htpasswd "$BASIC_AUTH_USER" "$BASIC_AUTH_PASS"

# Start Streamlit in the background
streamlit run app.py --server.address=127.0.0.1 --server.port=8501 &
# Start Nginx in the foreground
nginx -g 'daemon off;'

