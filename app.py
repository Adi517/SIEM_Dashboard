from flask import Flask, render_template, jsonify, request, redirect, url_for
from pymongo import MongoClient
import requests
import re
from dotenv import load_dotenv
import os
from datetime import datetime
from scapy.all import sniff
from flask_socketio import SocketIO
import time
from flask_cors import CORS
from zxcvbn import zxcvbn  # Make sure to install zxcvbn-python
from flask import Flask, request, jsonify, render_template
import pandas as pd
import pickle
import psutil
import platform
import cpuinfo
import socket
import joblib
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import ssl
import socket
import datetime
import wmi
import pythoncom
import threading
import subprocess


# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("API key not found. Make sure it's set in your .env file.")

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
# CORS(app)  # Enable Cross-Origin Resource Sharing

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client['DNSMonitoring']
ip_logs_collection = db['IPLogs']

# Extract IPs from dns_cache.txt
def extract_ips():
    try:
        with open('dns_cache.txt', 'r') as file:
            content = file.read()
        ips = re.findall(r'A \(Host\) Record .+?:\s+(\d+\.\d+\.\d+\.\d+)', content)
        return list(set(ips))  # Remove duplicates
    except FileNotFoundError:
        return []

# Check IPs using VirusTotal API
def check_ip(ip):
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'ip': ip}
    
    try:
        response = requests.get(url, params=params)
        if response.status_code != 200:
            print(f"Error {response.status_code}: {response.text}")
            return None
        return response.json()
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def process_packet(packet):
    if packet.haslayer('IP'):
        data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": packet['IP'].src,
            "destination": packet['IP'].dst,
            "protocol": "TCP" if packet.haslayer('TCP') else "UDP" if packet.haslayer('UDP') else "Other",
            "size": len(packet)
        }
        socketio.emit('new_packet', data)




# Static Information (only fetch once)
def get_static_info():
    uname = platform.uname()
    cpu_info = cpuinfo.get_cpu_info()
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.datetime.fromtimestamp(boot_time_timestamp)

    return {
        "system_name": socket.gethostname(),
        "os": uname.system,
        "os_version": uname.version,
        "machine": uname.machine,
        "processor": uname.processor,
        "cpu_brand": cpu_info['brand_raw'],
        "cpu_cores": psutil.cpu_count(logical=False),
        "cpu_threads": psutil.cpu_count(logical=True),
        "boot_time": bt.strftime("%Y-%m-%d %H:%M:%S"),
    }

# Dynamic Information (refresh every few seconds)
def get_dynamic_info():
    cpu_temp = None
    try:
        pythoncom.CoInitialize()
        w = wmi.WMI(namespace="root\\wmi")
        temperature_info = w.MSAcpi_ThermalZoneTemperature()
        if temperature_info:
            temp = temperature_info[0].CurrentTemperature
            cpu_temp = (temp / 10.0) - 273.15
    except Exception as e:
        print(f"Error fetching CPU temperature: {e}")
    finally:
        pythoncom.CoUninitialize()

    return {
        "cpu_usage_percent": psutil.cpu_percent(),
        "cpu_temperature": cpu_temp,
        "uptime": str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())),
        "memory_total": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "memory_used": round(psutil.virtual_memory().used / (1024 ** 3), 2),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_total": round(psutil.disk_usage('/').total / (1024 ** 3), 2),
        "disk_used": round(psutil.disk_usage('/').used / (1024 ** 3), 2),
        "disk_percent": psutil.disk_usage('/').percent,
        "ip_address": socket.gethostbyname(socket.gethostname()),
    }


@app.route('/')
def home():
    logs = ip_logs_collection.find().sort("date", -1)
    return render_template('index.html', logs=logs)

@app.route('/scan')
def scan():
    ips = extract_ips()
    results = []

    for ip in ips:
        response = check_ip(ip)
        if response:
            malicious = response.get("detected_urls", []) != []
            result = {
                "ip": ip,
                "malicious": malicious,
                "details": response,
                "date": datetime.now()
            }
            inserted_id = ip_logs_collection.insert_one(result).inserted_id
            result["_id"] = str(inserted_id)  
            results.append(result)
    return jsonify({"message": "Scan Complete", "results": results})

@app.route('/network_monitor')
def network_monitor():
    return render_template('network_monitor.html')

@app.route('/system')
def system_info():
    static_info = get_static_info()
    return render_template('system.html', static_info=static_info)

# Emit dynamic data every 5 minutes (300 seconds)
def emit_dynamic_info():
    while True:
        data = get_dynamic_info()
        socketio.emit('update_info', data)
        time.sleep(5)  # <-- Change to 5 for testing: time.sleep(5)

@socketio.on('connect')
def on_connect():
    print('Client connected')

@app.route('/system/generate')
def generate_report():
    report_path = os.path.expanduser("~\\battery-report.html")
    try:
        subprocess.run(["powercfg", "/batteryreport", "/output", report_path], check=True, shell=True)
        return redirect(url_for('show_report'))
    except subprocess.CalledProcessError:
        return "❌ Failed to generate battery report."

@app.route('/system/report')
def show_report():
    report_path = os.path.expanduser("~\\battery-report.html")
    if os.path.exists(report_path):
        with open(report_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return render_template('report.html', report_html=content)
    else:
        return "⚠️ Report not found. Please generate it first."
@app.route('/password')
def password_page():
    return render_template('password.html')

@app.route('/password/analyze', methods=['POST'])
def analyze():
    data = request.json
    password = data.get('password')

    if not password:
        return jsonify({"error": "No password provided"}), 400

    result = zxcvbn(password)

    strength = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'][result['score']]
    suggestions = result['feedback']['suggestions']

    response = {
        "strength": strength,
        "suggestions": suggestions if suggestions else ["Good password!"]
    }

    return jsonify(response)



loaded_model = pickle.load(open('phishing.pkl', 'rb'))

@app.route('/phishing')
def phishing_page():
    return render_template('phishing.html')

@app.route('/phishing/predict', methods=['POST'])
def predict_phishing():
    try:
        url = request.form['url']
        predict_urls = [url]
        prediction = loaded_model.predict(predict_urls)
        return jsonify({'result': prediction[0]})
    except Exception as e:
        print("❌ Error during prediction:", e)
        return jsonify({'error': 'Prediction failed. Please check server logs.'}), 500

socketio.start_background_task(sniff, prn=process_packet, store=False, iface="Wi-Fi", filter="ip")

threading.Thread(target=emit_dynamic_info).start()

socketio.run(app, debug=True, host='0.0.0.0', port=5000) 



# @app.route('/phishing/predict', methods=['POST'])
# def predict_phishing():
#     try:
#         url = request.form['url']

#         # 1. Run ML model prediction
#         predict_urls = [url]
#         prediction = loaded_model.predict(predict_urls)[0]

#         # 2. Run SSL Certificate Validation
#         ssl_result = check_ssl_certificate(url)

#         # 3. Combine result
#         return jsonify({
#             'prediction': prediction,
#             'ssl_check': ssl_result
#         })

#     except Exception as e:
#         print("❌ Error during prediction:", e)
#         return jsonify({'error': 'Prediction failed. Please check server logs.'}), 500

# @app.route('/system-info')
# def system_info():
#     return jsonify(get_system_info())


# def check_ssl_certificate(url):
#     try:
#         hostname = url.replace("https://", "").replace("http://", "").split('/')[0]

#         context = ssl.create_default_context()
#         print("Started")
#         with socket.create_connection((hostname, 443), timeout=5) as sock:
#             print("Hello")
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 print("Hi")
#                 cert = ssock.getpeercert()
#                 expire_date_str = cert['notAfter']
#                 print("Me")
#                 # Convert 'notAfter' string to datetime object
#                 expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
#                 print("done ...")
#                 # Check if certificate is still valid
#                 # expire_date > datetime.now(timezone.utc)
#                 print("Started")
#                 return {
#                     'ssl_supported': True,
#                     'certificate_valid': "valid",
#                     'valid_from': cert.get('notBefore'),
#                     'valid_to': cert.get('notAfter')
#                 }

#     except Exception as e:
#         return {
#             'ssl_supported': False,
#             'certificate_valid': False,
#             'error': str(e)
#         }



# import pythoncom  # Add this import at the top

# def get_system_info():
#     import platform
#     import cpuinfo
#     import psutil
#     import socket
#     import datetime
#     import wmi

#     uname = platform.uname()
#     cpu_info = cpuinfo.get_cpu_info()

#     # CPU temperature (Windows only)
#     cpu_temp = None
#     try:
#         pythoncom.CoInitialize()  # Initialize COM for this thread
#         w = wmi.WMI(namespace="root\\wmi")
#         temperature_info = w.MSAcpi_ThermalZoneTemperature()
#         if temperature_info:
#             temp = temperature_info[0].CurrentTemperature
#             cpu_temp = (temp / 10.0) - 273.15
#     except Exception as e:
#         print(f"Error fetching CPU temperature: {e}")
#     finally:
#         pythoncom.CoUninitialize()  # Uninitialize COM when done

#     boot_time_timestamp = psutil.boot_time()
#     bt = datetime.datetime.fromtimestamp(boot_time_timestamp)

#     info = {
#         "system_name": socket.gethostname(),
#         "os": uname.system,
#         "os_version": uname.version,
#         "machine": uname.machine,
#         "processor": uname.processor,
#         "cpu_brand": cpu_info['brand_raw'],
#         "cpu_cores": psutil.cpu_count(logical=False),
#         "cpu_threads": psutil.cpu_count(logical=True),
#         "cpu_usage_percent": psutil.cpu_percent(),
#         "cpu_temperature": cpu_temp,
#         "boot_time": bt.strftime("%Y-%m-%d %H:%M:%S"),
#         "uptime": str(datetime.datetime.now() - bt),
#         "memory_total": round(psutil.virtual_memory().total / (1024 ** 3), 2),
#         "memory_used": round(psutil.virtual_memory().used / (1024 ** 3), 2),
#         "memory_percent": psutil.virtual_memory().percent,
#         "disk_total": round(psutil.disk_usage('/').total / (1024 ** 3), 2),
#         "disk_used": round(psutil.disk_usage('/').used / (1024 ** 3), 2),
#         "disk_percent": psutil.disk_usage('/').percent,
#         "ip_address": socket.gethostbyname(socket.gethostname()),
#     }
#     return info



# Flask Routes
# @app.route('/system')
# def system_info():
#     static_info = get_static_info()
#     dynamic_info = get_dynamic_info()
#     return render_template('system.html', static_info=static_info, dynamic_info=dynamic_info)

# @app.route('/system/dynamic')
# def system_dynamic():
#     return jsonify(get_dynamic_info())