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
cur_ip = None
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
conn = sqlite3.connect('users.db')
c = conn.cursor()
firewall_ip = c.execute('SELECT IP FROM ips').fetchone()
conn.close()
OPNSENSE_HOST = f"http://{firewall_ip[0]}"
API_KEY = "jrvyX2oH6Ofqp/7BHfC+3YyBq8YTU3PkcGSKKC6XabZGWKZ9OkDkzp8kUtdsxvKTZ60aw2OtcOXUEw5E"
API_SECRET = "bz92B/FFBOWs1CNrweoJ3iV8N4tkA8Rdf3KMfqzj9lTJ3zMOMbPbqOn9H+TMs2M8e7k2ae7vt4fbsc5x"
auth = (API_KEY, API_SECRET)
sent_bytes = []
interfaces = []
url = f"{OPNSENSE_HOST}/api/diagnostics/interface/getInterfaceStatistics"
@app.route("/")
@login_required
def home():
    return render_template("index.html")
@app.route("/get-interfaces")
def get_interfaces():
    global sent_bytes,interfaces
    interfaces = []
    packets_ps = requests.get(url,auth=(API_KEY,API_SECRET))
    data = packets_ps.json()
    for interface in data['statistics']:
        if('Loopback' not in interface and ':' not in interface):
            interfaces.append(interface)
    sent_bytes = [[] for i in range(len(interfaces))]
    return jsonify({'interfaces':interfaces})
@app.route('/firewalltraffic', methods=['GET'])
def get_traffic_value():
    try:
        response = requests.get(url, auth=(API_KEY, API_SECRET))
        data = response.json()
        stats = data['statistics']
        traffic_data = {}
        c = 0
        for interface in stats:
            if 'Loopback' not in interface and ':' not in interface:
                sent_bytes[c].append(stats[interface]['sent-bytes'])
                c+=1
        if(len(sent_bytes[0]) >= 2):
            for i in range(len(sent_bytes)):
                l = len(sent_bytes[i])
                traffic_data[interfaces[i]] = abs(sent_bytes[i][l-1]-sent_bytes[i][l-2])
        return jsonify(traffic_data)
    except Exception as e:
        return jsonify(f"Error: {e}")
@app.route('/addrule', methods=['GET', 'POST'])
@login_required
def add_rule():
    return render_template('add_rule.html')
@app.route("/firewallip",methods=['GET','POST'])
@login_required
def edit_firewall_ip():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if(request.method == "POST"):
        ip = request.form["ip"]
        c.execute('INSERT INTO ips (IP) VALUES (?)',(ip,))
        conn.commit()
    cur_ip = c.execute("SELECT * FROM ips").fetchall()
    print(cur_ip)
    conn.close()
    return render_template("editfirewallip.html",cur_ip = cur_ip)
@app.route("/update_firewall_ip/<int:id>",methods=['GET','POST'])
def update_firewall_ip(id):
    id = int(id)
    global OPNSENSE_HOST
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    firewall_ip = c.execute('SELECT IP FROM ips').fetchone()
    if(request.method == "POST"):
        ip = request.form["ip"]
        c.execute('UPDATE ips SET IP = ? WHERE ID = ?',(ip,id))
        conn.commit()
        conn.close()
        OPNSENSE_HOST = f"http://{ip}"
        return redirect(url_for('edit_firewall_ip'))
    return render_template("update_firewall_ip.html",firewall_ip = firewall_ip[0])

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
            return redirect(url_for('home'))
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

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)

