from flask import Flask, request, render_template, jsonify
from flask_login import login_required
from queue import Queue
import json
import subprocess
import threading

class CommandThread(threading.Thread):
    def __init__(self,interface):
        super(CommandThread, self).__init__()
        self.interface = interface
        self._stop_event = threading.Event()

    def run(self):
        commands = ["g++ capturesumma.c -lpcap -lcjson -lcurl -o cap.out", f"sudo ./cap.out {self.interface}"]
        for command in commands:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if self._stop_event.is_set():
                break


app = Flask(__name__)

# Global queue to hold packets
packet_queue = Queue()

@app.route("/")
def home():
    return "Home"

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
    print("Retrieved packets:", packets)
    return jsonify(packets)
@app.route("/viewlivepackets/<string:interface>")
def viewliveinterface(interface):
    command_thread = CommandThread(interface)
    command_thread.start()
    return render_template("traffic.html", interface=interface)

if __name__ == "__main__":
    app.run(debug=True)
