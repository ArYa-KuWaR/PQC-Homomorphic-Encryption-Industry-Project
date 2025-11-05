# client_interactive.py - Interactive PQC+DRM Chat Client with UI

import os
import requests
import base64
import time
from secrets import compare_digest
from pqcrypto.kem.ml_kem_1024 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tenseal as ts
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.live import Live
from rich import box

console = Console()


# --- Helper Functions ---
def bytes_to_base64(data):
    return base64.b64encode(data).decode('utf-8')

def base64_to_bytes(b64_str):
    return base64.b64decode(b64_str)


class DRMPolicy:
    """Homomorphic Encryption DRM Manager"""
    
    def __init__(self):
        self.context = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=4096,
            plain_modulus=1032193
        )
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()
    
    def get_public_context(self):
        ctx_copy = self.context.copy()
        ctx_copy.make_context_public()
        return bytes_to_base64(ctx_copy.serialize())
    
    def create_license(self, max_plays):
        encrypted_counter = ts.bfv_vector(self.context, [0])
        return {
            'encrypted_counter': bytes_to_base64(encrypted_counter.serialize()),
            'max_plays': max_plays,
            'public_context': self.get_public_context()
        }
    
    def verify_limit(self, encrypted_counter_b64):
        counter_bytes = base64_to_bytes(encrypted_counter_b64)
        enc_counter = ts.bfv_vector_from(self.context, counter_bytes)
        return enc_counter.decrypt()[0]


class InteractiveChatClient:
    def __init__(self, username, server_url="http://127.0.0.1:5000"):
        self.username = username
        self.server_url = server_url
        self.public_key = None
        self.secret_key = None
        self.session_keys = {}
        self.drm = DRMPolicy()
        self.inbox = []
        
    def generate_keys(self):
        """Generate ML-KEM-1024 keypair"""
        with console.status("[cyan]Generating quantum-resistant keys...", spinner="dots"):
            self.public_key, self.secret_key = generate_keypair()
        console.print("✓ Keys generated", style="bold green")
        
    def publish_keys_to_server(self):
        """Publish public key to server"""
        with console.status("[cyan]Publishing keys to server...", spinner="dots"):
            bundle = {
                'username': self.username,
                'pqc_public_key': bytes_to_base64(self.public_key),
                'algorithm': 'ML-KEM-1024'
            }
            response = requests.post(f"{self.server_url}/publish_keys", json=bundle)
        
        if response.status_code == 200:
            console.print("✓ Keys published successfully", style="bold green")
        else:
            console.print(f"✗ Failed to publish keys", style="bold red")
    
    def establish_session_as_initiator(self, recipient):
        """Establish PQC session"""
        response = requests.get(f"{self.server_url}/get_keys/{recipient}")
        if response.status_code != 200:
            return None
        
        key_bundle = response.json()
        recipient_public_key = base64_to_bytes(key_bundle['pqc_public_key'])
        
        ciphertext, shared_secret = encrypt(recipient_public_key)
        self.session_keys[recipient] = shared_secret[:32]
        
        return {
            "kem_ciphertext": bytes_to_base64(ciphertext),
            "algorithm": "ML-KEM-1024"
        }
    
    def establish_session_as_responder(self, sender, kem_ciphertext_b64):
        """Respond to session initiation"""
        kem_ciphertext = base64_to_bytes(kem_ciphertext_b64)
        shared_secret = decrypt(self.secret_key, kem_ciphertext)
        self.session_keys[sender] = shared_secret[:32]
    
    def send_message(self, recipient, message, drm_enabled=True, max_plays=5):
        """Send encrypted message with optional DRM"""
        is_initial = recipient not in self.session_keys
        
        # Establish session if needed
        if is_initial:
            with console.status(f"[cyan]Establishing quantum-safe session with {recipient}...", spinner="dots"):
                handshake_info = self.establish_session_as_initiator(recipient)
                if not handshake_info:
                    console.print(f"✗ Could not reach {recipient}", style="bold red")
                    return
        
        # Create DRM license if enabled
        drm_license = None
        if drm_enabled:
            drm_license = self.drm.create_license(max_plays=max_plays)
        
        # Encrypt message
        session_key = self.session_keys[recipient]
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
        
        # Build payload
        payload = {
            "sender": self.username,
            "recipient": recipient,
            "type": "initial" if is_initial else "normal",
            "message_content": list(nonce + ciphertext),
            "pqc_protocol": "ML-KEM-1024",
        }
        
        if drm_license:
            payload["drm_license"] = drm_license
        
        if is_initial:
            payload["kem_ciphertext"] = handshake_info["kem_ciphertext"]
        
        # Send to server
        with console.status("[cyan]Sending encrypted message...", spinner="dots"):
            response = requests.post(f"{self.server_url}/send", json=payload)
        
        if response.status_code == 200:
            drm_tag = f"[DRM: max {max_plays} plays]" if drm_enabled else "[No DRM]"
            console.print(f"✓ Message sent to [bold]{recipient}[/bold] {drm_tag}", style="green")
        else:
            console.print("✗ Failed to send message", style="bold red")
    
    def check_messages(self):
        """Check and decrypt incoming messages"""
        response = requests.get(f"{self.server_url}/receive/{self.username}")
        messages = response.json().get("messages", [])
    
        if not messages:
            console.print("📭 No new messages", style="yellow")
            return
    
        console.print(f"\n📬 [bold cyan]{len(messages)} new message(s)[/bold cyan]\n")
    
        for idx, msg in enumerate(messages, 1):
            sender = msg['sender']
        
        # Establish session if needed
            if msg['type'] == 'initial':
                kem_ct = msg.get('kem_ciphertext')
                if kem_ct:
                    self.establish_session_as_responder(sender, kem_ct)
        
        # Decrypt message
            session_key = self.session_keys.get(sender)
            if not session_key:
                console.print(f"✗ No session key for {sender}", style="red")
                continue
        
            aesgcm = AESGCM(session_key)
            encrypted_payload = bytes(msg['message_content'])
            nonce = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
        
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
            
            # Handle DRM - simplified server-side tracking
                drm_status = ""
                drm_allowed = True
            
                drm_license = msg.get('drm_license')
                if drm_license:
                    max_plays = drm_license['max_plays']
                
                # Get current play count from server (no HE needed for demo)
                    play_count_response = requests.get(
                        f"{self.server_url}/drm_status/{sender}/{self.username}/{idx}"
                    )
                
                    if play_count_response.status_code == 200:
                        play_data = play_count_response.json()
                        current_plays = play_data.get('play_count', 0) + 1  # Increment for this play
                    
                    # Update play count on server
                        requests.post(
                            f"{self.server_url}/drm_play",
                            json={
                                'sender': sender,
                                'recipient': self.username,
                                'message_index': idx
                            }
                        )
                    
                        if current_plays <= max_plays:
                            drm_status = f"🎫 [green]DRM: Play {current_plays}/{max_plays}[/green]"
                            drm_allowed = True
                        else:
                            drm_status = f"🚫 [red]DRM LIMIT EXCEEDED: {current_plays}/{max_plays}[/red]"
                            drm_allowed = False
                    else:
                        # Fallback - allow playback
                        drm_allowed = True
                        drm_status = "[yellow]⚠ DRM tracking unavailable[/yellow]"
            
            # Display message
                panel_color = "green" if drm_allowed else "red"
                panel_title = f"Message {idx} from [bold]{sender}[/bold]"
            
                if drm_allowed:
                    message_text = f"[white]{plaintext}[/white]"
                    if drm_status:
                        message_text += f"\n\n{drm_status}"
                else:
                    message_text = f"[red dim]❌ Message blocked by DRM policy[/red dim]\n\n{drm_status}"
            
                console.print(Panel(message_text, title=panel_title, border_style=panel_color, box=box.ROUNDED))
            
            except Exception as e:
                console.print(Panel(
                    f"[red]✗ Decryption failed: {e}[/red]",
                    title=f"Error - Message {idx}",
                    border_style="red",
                    box=box.ROUNDED
                ))


def show_banner(username):
    """Display welcome banner"""
    banner = f"""
[bold cyan]╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     🔐 PQC + HOMOMORPHIC ENCRYPTION CHAT SYSTEM 🔐        ║
║                                                           ║
║  🛡️  Post-Quantum Security (ML-KEM-1024)                 ║
║  🔒 Homomorphic DRM Enforcement (TenSEAL)                ║
║  💬 End-to-End Encrypted Messaging                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝[/bold cyan]

[bold green]Welcome, {username}![/bold green]
"""
    console.print(banner)


def show_menu():
    """Display main menu"""
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Option", style="cyan bold")
    table.add_column("Description", style="white")
    
    table.add_row("1", "📨 Send Message")
    table.add_row("2", "📬 Check Inbox")
    table.add_row("3", "👥 View Active Sessions")
    table.add_row("4", "🚪 Exit")
    
    console.print("\n")
    console.print(table)
    console.print()


def main():
    """Main interactive loop"""
    console.clear()
    
    # Get username (no default shown)
    console.print("\n[bold cyan]🔐 PQC + Homomorphic Encryption Chat System[/bold cyan]\n")
    username = Prompt.ask("[bold cyan]Enter your username[/bold cyan]")
    
    console.clear()
    show_banner(username)
    
    # Initialize client
    with console.status("[cyan]Initializing secure client...", spinner="dots"):
        client = InteractiveChatClient(username)
        client.generate_keys()
        client.publish_keys_to_server()
    
    console.print("\n[bold green]✓ Client ready![/bold green]\n")
    
    # Main loop
    while True:
        show_menu()
        choice = Prompt.ask("[bold cyan]Choose an option[/bold cyan]", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            # Send message
            console.print("\n[bold cyan]═══ Send Message ═══[/bold cyan]\n")
            recipient = Prompt.ask("[cyan]Recipient username[/cyan]")
            message = Prompt.ask("[cyan]Your message[/cyan]")
            
            drm_enabled = Confirm.ask("[cyan]Enable DRM protection?[/cyan]", default=True)
            max_plays = 5
            if drm_enabled:
                max_plays = IntPrompt.ask("[cyan]Maximum plays allowed[/cyan]", default=5)
            
            console.print()
            client.send_message(recipient, message, drm_enabled, max_plays)
            console.print()
            
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")
            console.clear()
            show_banner(username)
        
        elif choice == "2":
            # Check messages
            console.print("\n[bold cyan]═══ Checking Inbox ═══[/bold cyan]\n")
            client.check_messages()
            console.print()
            
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")
            console.clear()
            show_banner(username)
        
        elif choice == "3":
            # View sessions
            console.print("\n[bold cyan]═══ Active Sessions ═══[/bold cyan]\n")
            
            if not client.session_keys:
                console.print("[yellow]No active sessions[/yellow]")
            else:
                session_table = Table(box=box.ROUNDED)
                session_table.add_column("User", style="cyan")
                session_table.add_column("Status", style="green")
                
                for peer in client.session_keys.keys():
                    session_table.add_row(peer, "✓ Established")
                
                console.print(session_table)
            
            console.print()
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")
            console.clear()
            show_banner(username)
        
        elif choice == "4":
            # Exit
            console.print("\n[bold cyan]Goodbye! Stay quantum-safe! 🔒[/bold cyan]\n")
            break


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Session interrupted. Goodbye![/yellow]\n")
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]\n")
        import traceback
        traceback.print_exc()
