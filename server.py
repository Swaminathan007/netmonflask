from flask import *
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
import scapy.all as scapy
import os
from collections import deque
from queue import Queue
packet_queue = Queue()

class CommandThread(threading.Thread):
    def __init__(self,interface):
        super(CommandThread, self).__init__()
        self.interface = interface
        self._stop_event = threading.Event()

    def run(self):
        commands = ["g++ capture.c -lpcap -lcjson -lcurl -o cap.out", f"sudo ./cap.out {self.interface}"]
        for command in commands:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if self._stop_event.is_set():
                break

command_thread = None
app = Flask(__name__)
app.secret_key = 'my_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

OPNsense_API_URL = 'https://192.168.229.131'
OPNsense_API_KEY = "nl7PdG0PiMBMelsy11A8oOpODUYD2nLDOqJihihpogB83I6rTr2oFr7cYEggSyvqTr3CvJ6zqZ2ZX08c"
OPNsense_API_SECRET = "s/OMjoybJx0OTD/+l8V7lLOH4/NZ+B68qPsyW7OM2QAbo+QWPawewY8QgZ5G/TEfjH0Q/TGFhSLk7Q7A"
auth = HTTPBasicAuth(OPNsense_API_KEY, OPNsense_API_SECRET)
if not OPNsense_API_KEY or not OPNsense_API_SECRET:
    raise ValueError("API Key and Secret must be set as environment variables.")
# User model
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password
        
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], password=user[2])
    return None


OPNSENSE_HOST = "http://192.168.229.131"
API_KEY = "jrvyX2oH6Ofqp/7BHfC+3YyBq8YTU3PkcGSKKC6XabZGWKZ9OkDkzp8kUtdsxvKTZ60aw2OtcOXUEw5E"
API_SECRET = "bz92B/FFBOWs1CNrweoJ3iV8N4tkA8Rdf3KMfqzj9lTJ3zMOMbPbqOn9H+TMs2M8e7k2ae7vt4fbsc5x"
auth = (API_KEY, API_SECRET)

# Endpoint for interface statistics
url = f"{OPNSENSE_HOST}/api/diagnostics/interface/getInterfaceStatistics"

@app.route('/')
@login_required
def index():
    return render_template('index.html')
def fetch_interface_statistics():
    while True:
        try:
            response = requests.get(url, auth=auth, verify=False)
            if response.status_code == 200:
                data = response.json()
                interface_stats = data.get("statistics", {}).get("[pflog0] / pflog0", {})
                bytes = int(interface_stats.get("sent-bytes", 0))
                yield f"data:{bytes}\n\n"
            else:
                yield f"data:0\n\n"
        except Exception as e:
            yield f"data:0\n\n"

@app.route('/firewall_traffic')
def random_data():
    return Response(fetch_interface_statistics(), mimetype='text/event-stream')
@app.route('/addrule', methods=['GET', 'POST'])
@login_required
def add_rule():
    if request.method == 'POST':
        rule = request.json['rule']
        # Add the rule to UFW
        result = subprocess.run(['sudo', 'ufw', 'allow', rule], capture_output=True, text=True)
        return jsonify({'result': result.stdout, 'error': result.stderr})
    return render_template('add_rule.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            user_obj = User(id=user[0], username=user[1], password=user[2])
            login_user(user_obj)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route("/adduser",methods = ["GET","POST"])
@login_required
def adduser():
    return render_template("adduser.html")
@app.route("/viewlivepackets")
@login_required
def viewlivepackets():
    interfaces = scapy.get_if_list()
    print(interfaces)
    return render_template("interfaces.html",interfaces=interfaces)

@app.route("/packet", methods=["POST"])
def receive_packet():
    packet_json = request.get_json()
    packet_queue.put(packet_json)
    return "Packet received", 200
@app.route("/get_packets")
def get_packets():
    packets = []
    while not packet_queue.empty():
        packets.append(packet_queue.get())
    return jsonify(packets)
@app.route("/viewlivepackets/<string:interface>")
def viewliveinterface(interface):
    command_thread = CommandThread(interface)
    command_thread.start()
    return render_template("traffic.html", interface=interface)

def tail_log():
    log_file = '/var/log/ufw.log'
    process = subprocess.Popen(['tail', '-f', log_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        line = process.stdout.readline().decode('utf-8').strip()
        if line:
            now = datetime.now()
            current_second = int(now.timestamp())
            if current_second not in log_count:
                log_count[current_second] = 0
                logs_per_second[current_second] = []
            log_count[current_second] += 1
            logs_per_second[current_second].append(line)

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)

