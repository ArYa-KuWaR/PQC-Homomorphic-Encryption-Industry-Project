# --- CORRECTED server.py ---

import os
import json
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

SERVER_MESSAGE_BOX_DIR = "server_messages"
os.makedirs(SERVER_MESSAGE_BOX_DIR, exist_ok=True)

key_bundles = {}

@app.route('/publish_keys', methods=['POST'])
def publish_keys():
    data = request.json
    username = data['username']
    key_bundles[username] = {
        'identity_key': data['identity_key'],
        'signed_pre_key': data['signed_pre_key'],
        'one_time_pre_keys': data['one_time_pre_keys'],
    }
    print(f"Received and stored key bundle for {username}")
    return jsonify({"status": f"keys for {username} stored"}), 200

@app.route('/get_keys/<username>', methods=['GET'])
def get_keys(username):
    if username not in key_bundles:
        return jsonify({"error": "user not found"}), 404
    bundle = key_bundles[username]
    if not bundle['one_time_pre_keys']:
        return jsonify({"error": "no more one-time keys for user"}), 500
    one_time_key = bundle['one_time_pre_keys'].pop(0)
    return jsonify({
        'username': username,
        'identity_key': bundle['identity_key'],
        'signed_pre_key': bundle['signed_pre_key'],
        'one_time_pre_key': one_time_key
    })


# --- THIS IS THE CORRECTED FUNCTION ---
@app.route('/send', methods=['POST'])
def send_message():
    # The entire JSON body is the message payload we want to store.
    message_payload = request.json
    
    # Get the recipient from inside the payload.
    recipient = message_payload.get('recipient')
    if not recipient:
        return jsonify({"error": "recipient not specified"}), 400

    recipient_dir = os.path.join(SERVER_MESSAGE_BOX_DIR, recipient)
    os.makedirs(recipient_dir, exist_ok=True)
    
    file_path = os.path.join(recipient_dir, f"{int(time.time() * 1000)}.json")
    with open(file_path, 'w') as f:
        # Save the entire payload, not just one part of it.
        json.dump(message_payload, f)
        
    print(f"Saved a message for {recipient}")
    return jsonify({"status": "message saved"}), 200


@app.route('/receive/<username>', methods=['GET'])
def receive_messages(username):
    user_dir = os.path.join(SERVER_MESSAGE_BOX_DIR, username)
    if not os.path.exists(user_dir):
        return jsonify({"messages": []}), 200
    all_messages = []
    message_files = os.listdir(user_dir)
    for file_name in message_files:
        file_path = os.path.join(user_dir, file_name)
        try:
            with open(file_path, 'r') as f:
                all_messages.append(json.load(f))
            os.remove(file_path)
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
    if all_messages:
        print(f"Delivering {len(all_messages)} messages to {username}")
    return jsonify({"messages": all_messages}), 200

if __name__ == '__main__':
    app.run(port=5000)