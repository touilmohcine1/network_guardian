from flask import Flask, render_template, jsonify
from threading import Thread
import sqlite3
import time
import os
from detector.arp_detector import start_arp_detection
from detector.dns_detector import start_dns_detection
from detector.ddos_detector import start_ddos_detection
from detector.scan_detector import start_scan_detection

app = Flask(__name__)

DB_PATH = 'database.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attack_type TEXT,
            description TEXT,
            source_ip TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, attack_type, description, source_ip FROM alerts ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return render_template('alerts.html', alerts=rows)

@app.route('/api/data')
def api_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type")
    data = cursor.fetchall()
    conn.close()
    result = {row[0]: row[1] for row in data}
    return jsonify(result)

def run_detectors():
    Thread(target=start_arp_detection, daemon=True).start()
    Thread(target=start_dns_detection, daemon=True).start()
    Thread(target=start_ddos_detection, daemon=True).start()
    Thread(target=start_scan_detection, daemon=True).start()

if __name__ == '__main__':
    init_db()
    run_detectors()
    app.run(host='0.0.0.0', port=5000, debug=True)
