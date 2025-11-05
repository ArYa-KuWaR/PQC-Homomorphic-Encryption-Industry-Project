# server.py - PQC + DRM Server with Auto-Delete Messages

import os
import json
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

SERVER_MESSAGE_BOX_DIR = "server_messages"
os.makedirs(SERVER_MESSAGE_BOX_DIR, exist_ok=True)

key_bundles = {}
drm_play_counts = {}  # Simple counter: {(sender, recipient, msg_idx): count}


@app.route('/publish_keys', methods=['POST'])
def publish_keys():
    """Store user's public keys"""
    try:
        data = request.json
        username = data['username']
        
        if 'pqc_public_key' in data:
            key_bundles[username] = {
                'pqc_public_key': data['pqc_public_key'],
                'algorithm': data.get('algorithm', 'ML-KEM-1024'),
                'type': 'pqc'
            }
            print(f"[PQC] ✓ Stored keys for {username}")
        else:
            key_bundles[username] = {
                'identity_key': data['identity_key'],
                'signed_pre_key': data['signed_pre_key'],
                'one_time_pre_keys': data['one_time_pre_keys'],
                'type': 'x3dh'
            }
            print(f"[X3DH] ✓ Stored keys for {username}")
        
        return jsonify({"status": "success"}), 200
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/get_keys/<username>', methods=['GET'])
def get_keys(username):
    """Retrieve user's public keys"""
    try:
        if username not in key_bundles:
            return jsonify({"error": "user not found"}), 404
        
        bundle = key_bundles[username]
        
        if bundle['type'] == 'pqc':
            return jsonify({
                'username': username,
                'pqc_public_key': bundle['pqc_public_key'],
                'algorithm': bundle['algorithm'],
                'type': 'pqc'
            }), 200
        else:
            if not bundle['one_time_pre_keys']:
                return jsonify({"error": "no one-time keys"}), 500
            
            otk = bundle['one_time_pre_keys'].pop(0)
            return jsonify({
                'username': username,
                'identity_key': bundle['identity_key'],
                'signed_pre_key': bundle['signed_pre_key'],
                'one_time_pre_key': otk,
                'type': 'x3dh'
            }), 200
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/send', methods=['POST'])
def send_message():
    """Store encrypted message"""
    try:
        message_payload = request.json
        recipient = message_payload.get('recipient')
        sender = message_payload.get('sender', 'unknown')
        
        if not recipient:
            return jsonify({"error": "no recipient"}), 400
        
        recipient_dir = os.path.join(SERVER_MESSAGE_BOX_DIR, recipient)
        os.makedirs(recipient_dir, exist_ok=True)
        
        timestamp = int(time.time() * 1000)
        file_path = os.path.join(recipient_dir, f"{timestamp}.json")
        
        with open(file_path, 'w') as f:
            json.dump(message_payload, f)
        
        has_drm = 'drm_license' in message_payload
        protocol = message_payload.get('pqc_protocol', 'x3dh')
        drm_tag = " [DRM]" if has_drm else ""
        
        print(f"[{protocol.upper()}]{drm_tag} ✓ Message from {sender} → {recipient} saved")
        
        return jsonify({"status": "saved", "timestamp": timestamp}), 200
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/receive/<username>', methods=['GET'])
def receive_messages(username):
    """Retrieve pending messages and delete them after reading"""
    try:
        user_dir = os.path.join(SERVER_MESSAGE_BOX_DIR, username)
        
        if not os.path.exists(user_dir):
            return jsonify({"messages": []}), 200
        
        all_messages = []
        files_to_delete = []
        
        for file_name in sorted(os.listdir(user_dir)):
            file_path = os.path.join(user_dir, file_name)
            try:
                with open(file_path, 'r') as f:
                    message = json.load(f)
                    all_messages.append(message)
                    files_to_delete.append(file_path)
            except Exception as e:
                print(f"⚠ Error reading {file_path}: {e}")
        
        # Delete messages after reading
        for file_path in files_to_delete:
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"⚠ Error deleting {file_path}: {e}")
        
        if all_messages:
            print(f"✓ Delivered {len(all_messages)} message(s) to {username} (deleted from server)")
        
        return jsonify({"messages": all_messages}), 200
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/drm_status/<sender>/<recipient>/<int:msg_idx>', methods=['GET'])
def drm_status(sender, recipient, msg_idx):
    """Get current DRM play count for a message"""
    key = (sender, recipient, msg_idx)
    play_count = drm_play_counts.get(key, 0)
    return jsonify({"play_count": play_count}), 200


@app.route('/drm_play', methods=['POST'])
def drm_play():
    """Increment DRM play count"""
    try:
        data = request.json
        sender = data['sender']
        recipient = data['recipient']
        msg_idx = data['message_index']
        
        key = (sender, recipient, msg_idx)
        drm_play_counts[key] = drm_play_counts.get(key, 0) + 1
        
        current_count = drm_play_counts[key]
        print(f"[DRM] ✓ Play count: {sender}→{recipient} msg#{msg_idx} = {current_count}")
        
        return jsonify({"status": "incremented", "count": current_count}), 200
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/status', methods=['GET'])
def status():
    """Server status and statistics"""
    total_messages = 0
    for username in os.listdir(SERVER_MESSAGE_BOX_DIR):
        user_dir = os.path.join(SERVER_MESSAGE_BOX_DIR, username)
        if os.path.isdir(user_dir):
            total_messages += len(os.listdir(user_dir))
    
    return jsonify({
        "status": "running",
        "registered_users": len(key_bundles),
        "users": list(key_bundles.keys()),
        "pending_messages": total_messages,
        "drm_tracked_messages": len(drm_play_counts),
        "features": ["PQC (ML-KEM-1024)", "E2EE", "DRM Tracking"]
    }), 200


@app.route('/clear_inbox/<username>', methods=['DELETE'])
def clear_inbox(username):
    """Clear all messages for a user (admin/debug endpoint)"""
    try:
        user_dir = os.path.join(SERVER_MESSAGE_BOX_DIR, username)
        
        if os.path.exists(user_dir):
            import shutil
            shutil.rmtree(user_dir)
            os.makedirs(user_dir)
            print(f"🗑️  Cleared inbox for {username}")
            return jsonify({"status": "cleared"}), 200
        else:
            return jsonify({"status": "already empty"}), 200
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  🔐 PQC + DRM SECURE MESSAGING SERVER")
    print("=" * 70)
    print("\n  Features:")
    print("    • Post-Quantum Cryptography (ML-KEM-1024)")
    print("    • End-to-End Encryption")
    print("    • DRM Play Counter Tracking")
    print("    • Auto-Delete Messages After Reading")
    print("\n" + "=" * 70)
    print("\n  Server starting on http://127.0.0.1:5000")
    print("  Press CTRL+C to stop\n")
    
    app.run(host='127.0.0.1', port=5000, debug=True)
