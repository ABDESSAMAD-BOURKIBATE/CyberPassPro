#!/bin/bash
echo "تشغيل CyberPassPro..."
source venv/bin/activate  # أو python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python CyberPassPro.py
