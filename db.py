# from werkzeug.security import generate_password_hash, check_password_hash
# import sqlite3
# def init_db():

#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         username TEXT UNIQUE NOT NULL,
#         password TEXT NOT NULL
#     )''')
    
#     # Insert sample users
#     sample_users = [
#         ('user1', generate_password_hash('password1')),
#         ('user2', generate_password_hash('password2'))
#     ]
#     c.executemany('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', sample_users)
#     conn.commit()
#     conn.close()
# init_db()

import subprocess

# Replace "interface" with the actual interface name
interface = "eth0"

# Command to run
command = ["sudo", "./cap.out", interface]

# Run the command
process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = process.communicate()

# Print the output
print("STDOUT:", stdout.decode())
print("STDERR:", stderr.decode())
