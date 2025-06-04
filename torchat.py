import base64
from PyQt5.QtGui import QPixmap, QImage, QTextDocument
from io import BytesIO
from PIL import Image
import os
import sys
import json
import time
import socket
import hashlib
import threading
import asyncio
import random
import stem.process
from stem.control import Controller
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                           QTextEdit, QStackedWidget, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64


# DHT implementation using Kademlia
import kademlia
from kademlia.network import Server

class TorDHTChat:
    def __init__(self, tor_path):
        self.tor_path = tor_path
        self.tor_process = None
        self.onion_service = None
        self.hidden_service_dir = os.path.join(os.path.expanduser("~"), ".tor_chat_hidden_service")
        self.dht_node = None
        self.onion_address = None
        self.users = {}
        self.socks_port = None
        self.control_port = None
        self.load_users()
        self.loop = asyncio.new_event_loop()
        
        # Create hidden service directory if it doesn't exist
        if not os.path.exists(self.hidden_service_dir):
            os.makedirs(self.hidden_service_dir)

    def get_static_salt(self, username):
        """Returns a consistent per-user salt for key derivation"""
        return hashlib.sha256(f"torchat_salt::{username}".encode()).digest()

    
    
    def get_username_by_onion(self, onion_id):
        """Finds the username that matches a given onion ID"""
        for username, data in self.users.items():
            if data.get("onion_id") == onion_id:
                return username
        return None



    def get_bootstrap_nodes(self):
        """Read the bootstrap node info if available"""
        return ["127.0.0.1:6881"]  # Ensure all users use the same bootstrap node

    
    def load_users(self):
        try:
            if os.path.exists("users.json"):
                with open("users.json", "r") as f:
                    self.users = json.load(f)
        except Exception as e:
            print(f"Error loading users: {e}")
            self.users = {}
    
    def save_users(self):
        try:
            with open("users.json", "w") as f:
                json.dump(self.users, f)
        except Exception as e:
            print(f"Error saving users: {e}")
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def signup(self, username, password):
        if username in self.users:
            return False, "Username already exists"
        
        hashed_password = self.hash_password(password)
        self.users[username] = {
            "password": hashed_password,
            "onion_id": None
        }
        self.save_users()
        return True, "User created successfully"
    
    def login(self, username, password):
        if username not in self.users:
            return False, "User does not exist"
        
        hashed_password = self.hash_password(password)
        if self.users[username]["password"] != hashed_password:
            return False, "Incorrect password"
        
        return True, "Login successful"
    
    def find_available_ports(self):
        """Find available ports for Tor SOCKS and control ports"""
        # Try to find available ports in range 9050-9150 for SOCKS
        # and 9051-9151 for Control
        for i in range(50):
            socks_port = 9050 + i*2
            control_port = 9051 + i*2
            
            # Check if ports are available
            socks_available = self.is_port_available(socks_port)
            control_available = self.is_port_available(control_port)
            
            if socks_available and control_available:
                return socks_port, control_port
        
        # If we couldn't find sequential ports, try random ports
        socks_port = self.find_random_available_port(10000, 60000)
        control_port = self.find_random_available_port(10000, 60000)
        
        return socks_port, control_port
    
    def is_port_available(self, port):
        """Check if a port is available"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", port))
            sock.close()
            return True
        except:
            return False
    
    def find_random_available_port(self, min_port, max_port):
        """Find a random available port in the given range"""
        for _ in range(100):  # Try up to 100 times
            port = random.randint(min_port, max_port)
            if self.is_port_available(port):
                return port
        raise RuntimeError("Could not find an available port")
    
    def start_tor(self):
        print("Finding available ports for Tor...")
        try:
            self.socks_port, self.control_port = self.find_available_ports()
            print(f"Using SOCKS port {self.socks_port} and Control port {self.control_port}")
            
            data_directory = os.path.join(os.path.expanduser("~"), f".tor_data_{self.socks_port}")
            if not os.path.exists(data_directory):
                os.makedirs(data_directory)
            
            print("Starting Tor process...")
            self.tor_process = stem.process.launch_tor_with_config(
                config={
                    'SocksPort': str(self.socks_port),
                    'ControlPort': str(self.control_port),
                    'DataDirectory': data_directory,
                    'CookieAuthentication': '1'
                },
                tor_cmd=self.tor_path,
                init_msg_handler=lambda line: print(f"Tor: {line}")
            )
            print("Tor started successfully")
            return True
        except Exception as e:
            print(f"Error starting Tor: {e}")
            return False
    

    def create_onion_service(self, username, port=5000):
        print("Creating persistent onion service...")
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                
                # Path to save/reuse the hidden service private key
                key_path = os.path.join(self.hidden_service_dir, f"{username}_hs_key")

                if os.path.exists(key_path):
                    print("[INFO] Found existing onion service key, reusing it.")
                    with open(key_path, "r") as f:
                        key_type, key_content = f.read().strip().split(":", 1)

                    response = controller.create_ephemeral_hidden_service(
                        {port: port},
                        key_type=key_type,
                        key_content=key_content,
                        await_publication=True
                    )
                else:
                    print("[INFO] No existing key found. Creating new onion service.")
                    response = controller.create_ephemeral_hidden_service(
                        {port: port},
                        await_publication=True
                    )
                    # Save private key for future reuse
                    with open(key_path, "w") as f:
                        f.write(f"{response.private_key_type}:{response.private_key}")
                    print(f"[INFO] Saved new onion service key to {key_path}")
                
                self.onion_address = response.service_id + ".onion"
                print(f"[INFO] Onion service created: {self.onion_address}")
                return self.onion_address
        except Exception as e:
            print(f"[ERROR] Failed to create persistent onion service: {e}")
            return None

    

    def start_dht_node(self, port=6881, bootstrap_nodes=None):
        print("[DEBUG] Starting DHT node...")

        try:
            # Check if there's already a bootstrap node stored
            if os.path.exists("bootstrap_node.json"):
                with open("bootstrap_node.json", "r") as f:
                    node = json.load(f)
                    bootstrap_nodes = [f"{node['host']}:{node['port']}"]
            else:
                bootstrap_nodes = []  # This instance becomes the first node in the network

            # If this is the first instance, save it as the bootstrap node
            if not bootstrap_nodes:
                with open("bootstrap_node.json", "w") as f:
                    json.dump({"host": "127.0.0.1", "port": port}, f)
                print(f"[INFO] This instance is the bootstrap node on port {port}")
            else:
                # Find a random available port for new clients
                port = self.find_random_available_port(5000, 9000)
                print(f"[INFO] New client using dynamic DHT port {port}, bootstrapping to {bootstrap_nodes[0]}")

            print(f"[DEBUG] Bootstrap nodes: {bootstrap_nodes}")

            self.dht_thread = threading.Thread(target=self._run_dht_server, 
                                            args=(port, bootstrap_nodes), 
                                            daemon=True)
            self.dht_thread.start()
            print(f"[DEBUG] DHT node started successfully on port {port}")

            return True
        except Exception as e:
            print(f"[ERROR] Error starting DHT node: {e}")
            return False
        
    def xor_obfuscate(self, data, key="torchat"):
        key_bytes = key.encode()
        data_bytes = data.encode()
        return ''.join(chr(b ^ key_bytes[i % len(key_bytes)]) for i, b in enumerate(data_bytes))

    def store_obfuscated_message(self, recipient_onion, plaintext, sender):
        obfuscated = base64.b64encode(self.xor_obfuscate(plaintext).encode()).decode()
        return self.store_message(recipient_onion, obfuscated, sender)


    def get_obfuscated_message(self, onion_id):
        msg = self.get_messages(onion_id)
        if msg:
            # Only perform obfuscation on text messages, not on images
            if msg and not msg.get("is_image", False):
                try:
                    # Make sure we're dealing with a string for text content
                    if isinstance(msg.get("content"), str):
                        decoded = base64.b64decode(msg["content"]).decode()
                        msg["content"] = self.xor_obfuscate(decoded)
                except Exception as e:
                    print(f"[WARNING] Failed to decode/obfuscate message: {e}")
            
            # Make sure to preserve the is_image flag
            return msg
        return None

   


            
    
    def _run_dht_server(self, port, bootstrap_nodes):
        asyncio.set_event_loop(self.loop)
        
        # Create the server
        self.loop.run_until_complete(self._setup_dht_server(port, bootstrap_nodes))
        
        # Run the event loop
        self.loop.run_forever()
    

    async def _setup_dht_server(self, port, bootstrap_nodes):
        self.dht_node = Server()
        await self.dht_node.listen(port)
        
        if bootstrap_nodes:
            print(f"[INFO] Bootstrapping to existing DHT nodes: {bootstrap_nodes}")
            try:
                await self.dht_node.bootstrap([(node.split(':')[0], int(node.split(':')[1])) for node in bootstrap_nodes])
                print("[INFO] Successfully connected to the DHT network")
            except Exception as e:
                print(f"[ERROR] Failed to bootstrap to DHT: {e}")
        else:
            print("[WARNING] No bootstrap nodes found. This instance will be the first DHT node.")

        print("[INFO] DHT server setup complete")
    
    def store_message(self, recipient_onion, message, sender, is_image=False):
        message_data = {
            "sender": sender,
            "content": message,
            "timestamp": time.time(),
            "read": False,  # Mark as unread initially
            "is_image": is_image  # Flag to indicate if this is an image
        }

        try:
            print(f"[DEBUG] Attempting to store message for {recipient_onion}")
            print(f"[DEBUG] Message content type: {'Image' if is_image else 'Text'}")
        
            future = asyncio.run_coroutine_threadsafe(
                self.dht_node.set(str(recipient_onion), json.dumps(message_data)),
                self.loop
            )
            try:
                future.result(timeout=5)
                print(f"[INFO] Message stored successfully for {recipient_onion}")
            except Exception as e:
                print(f"[ERROR] Failed to store message: {e}")

            print("[DEBUG] Message successfully stored in DHT!")  # Confirmation
            return True
        except Exception as e:
            print(f"[ERROR] Failed to store message: {e}")
            return False

    def get_messages(self, onion_id):
        """Retrieve messages from DHT and delete them after retrieval"""
        try:
            print(f"[DEBUG] Checking DHT for messages for {onion_id}")

            future = asyncio.run_coroutine_threadsafe(
                self.dht_node.get(str(onion_id)),
                self.loop
            )
            result = future.result(timeout=5.0)

            print(f"[DEBUG] Raw response from DHT: {result}")

            if result:
                try:
                    messages = json.loads(result)
                    print(f"[DEBUG] Messages found in DHT: {messages}")
                    
                    # Explicitly check for image flag
                    is_image = messages.get("is_image", False)
                    print(f"[DEBUG] Message type: {'Image' if is_image else 'Text'}")

                    # If it's an image, don't try to decode/obfuscate the content
                    if not is_image and not messages.get("is_encrypted", False):
                        try:
                            # Only decode/unobfuscate if it's regular text
                            if isinstance(messages.get("content"), str):
                                decoded = base64.b64decode(messages["content"]).decode()
                                messages["content"] = self.xor_obfuscate(decoded)
                        except Exception as e:
                            print(f"[WARNING] Failed to decode/obfuscate message: {e}")

                    # Generate a unique key to identify this specific message
                    message_id = f"{onion_id}_{messages['timestamp']}"
                    
                    # Store retrieved messages in a local cache
                    if not hasattr(self, 'processed_messages'):
                        self.processed_messages = set()
                    
                    # Check if we've already processed this message
                    if message_id in self.processed_messages:
                        print(f"[DEBUG] Message {message_id} already processed, skipping")
                        return None
                    
                    # Mark this message as processed
                    self.processed_messages.add(message_id)
                    
                    # Try to remove the message from the DHT
                    try:
                        delete_future = asyncio.run_coroutine_threadsafe(
                            self.dht_node.set(str(onion_id), ""),  # Clearing message from DHT
                            self.loop
                        )
                        delete_future.result(timeout=5.0)
                        print(f"[DEBUG] Deleted message {message_id} from DHT")
                    except Exception as e:
                        print(f"[WARNING] Failed to delete message from DHT: {e}")

                    return messages
                except json.JSONDecodeError as e:
                    print(f"[ERROR] Failed to parse message JSON: {e}")
                    return None
            print("[DEBUG] No messages found in DHT.")
            return None

        except asyncio.TimeoutError:
            print("[ERROR] Timeout while getting messages.")
            return None
        except Exception as e:
            print(f"[ERROR] Error getting messages: {e}")
            return None
   


    def stop(self):
        # Delete bootstrap_node.json if it exists
        try:
            if os.path.exists("bootstrap_node.json"):
                os.remove("bootstrap_node.json")
                print("[INFO] Removed bootstrap_node.json")
        except Exception as e:
            print(f"[ERROR] Failed to remove bootstrap_node.json: {e}")
        
        if self.loop and self.loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(self._shutdown_dht(), self.loop)
                self.loop.call_soon_threadsafe(self.loop.stop)
            except Exception as e:
                print(f"Error shutting down DHT: {e}")
        
        if self.tor_process:
            try:
                self.tor_process.kill()
                print("Tor process terminated")
            except Exception as e:
                print(f"Error terminating Tor: {e}")
   
    
    async def _shutdown_dht(self):
        if self.dht_node:
            await self.dht_node.stop()
            print("DHT node stopped")


class SignalsEmitter(QObject):
    message_received = pyqtSignal(str, str)
    status_update = pyqtSignal(str)



class ChatGUI(QMainWindow):
    def __init__(self, tor_path):
        super().__init__()
        self.tor_dht_chat = TorDHTChat(tor_path)
        self.signals = SignalsEmitter()
        self.current_user = None
        self.contacts = {}
        self.init_ui()
        
        # Background message checker
        self.message_checker_thread = None
        self.running = False
        
        # Connect signals
        self.signals.message_received.connect(self.update_chat_window)
        self.signals.status_update.connect(self.update_status)
        
    def init_ui(self):
        self.setWindowTitle("Serverless Tor DHT Chat")
        self.setGeometry(100, 100, 800, 600)
        
        # Create main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        self.main_layout.addWidget(self.stacked_widget)
        
        # Create login page
        self.create_login_page()
        
        # Create signup page
        self.create_signup_page()
        
        # Create chat page
        self.create_chat_page()
        
        # Add status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Start with login page
        self.stacked_widget.setCurrentIndex(0)

    def closeEvent(self, event):
        """Handle the window close event to properly shutdown TorDHTChat"""
        print("[INFO] Application closing, cleaning up resources...")
        self.running = False
        if self.message_checker_thread and self.message_checker_thread.is_alive():
            self.message_checker_thread.join(1)
        
        # Make sure to call the stop method to clean up resources
        self.tor_dht_chat.stop()
        
        # Accept the close event
        event.accept()
    
    def create_login_page(self):
        login_widget = QWidget()
        login_layout = QVBoxLayout(login_widget)
        
        title_label = QLabel("Login")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        
        login_button = QPushButton("Login")
        login_button.clicked.connect(self.handle_login)
        
        signup_button = QPushButton("Create Account")
        signup_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        
        login_layout.addWidget(title_label)
        login_layout.addLayout(username_layout)
        login_layout.addLayout(password_layout)
        login_layout.addWidget(login_button)
        login_layout.addWidget(signup_button)
        
        self.stacked_widget.addWidget(login_widget)
    
    def create_signup_page(self):
        signup_widget = QWidget()
        signup_layout = QVBoxLayout(signup_widget)
        
        title_label = QLabel("Create Account")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        self.signup_username_input = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.signup_username_input)
        
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        self.signup_password_input = QLineEdit()
        self.signup_password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.signup_password_input)
        
        confirm_layout = QHBoxLayout()
        confirm_label = QLabel("Confirm:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        confirm_layout.addWidget(confirm_label)
        confirm_layout.addWidget(self.confirm_password_input)
        
        signup_button = QPushButton("Sign Up")
        signup_button.clicked.connect(self.handle_signup)
        
        back_button = QPushButton("Back to Login")
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        signup_layout.addWidget(title_label)
        signup_layout.addLayout(username_layout)
        signup_layout.addLayout(password_layout)
        signup_layout.addLayout(confirm_layout)
        signup_layout.addWidget(signup_button)
        signup_layout.addWidget(back_button)
        
        self.stacked_widget.addWidget(signup_widget)
    

    def send_image(self):
        """Handle sending an image"""
        from PyQt5.QtWidgets import QFileDialog

        if not hasattr(self, 'current_recipient') or not self.current_recipient:
            QMessageBox.warning(self, "Error", "Please select a recipient first")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", "Image Files (*.png *.jpg *.jpeg *.gif *.bmp)"
        )
        if not file_path:
            return  # User canceled selection

        try:
            with Image.open(file_path) as img:
                # Resize and compress image to fit under DHT size constraints
                max_size = (300, 200)
                img.thumbnail(max_size, Image.LANCZOS)

                buffer = BytesIO()
                img = img.convert("RGB")  
                img.save(buffer, format="JPEG", quality=40)
                buffer.seek(0)

                img_base64 = base64.b64encode(buffer.read()).decode('utf-8')
                print(f"[DEBUG] Base64 image size: {len(img_base64)} characters")

                # Display a preview using original file
                preview_pixmap = QPixmap(file_path)
                preview_pixmap = preview_pixmap.scaled(300, 200, aspectRatioMode=Qt.KeepAspectRatio)

                # Store in DHT
                self.signals.status_update.emit(f"Sending image to {self.current_recipient}...")
                
                # Create a proper message object
                if self.tor_dht_chat.store_message(
                    self.current_recipient,
                    img_base64,
                    self.current_user,
                    is_image=True  
                ):
                    self.chat_window.append("You: [Image sent]")
                    self.display_image_in_chat(pixmap=preview_pixmap)
                    self.signals.status_update.emit("Image sent")
                else:
                    QMessageBox.warning(self, "Error", "Failed to send image. DHT may be unavailable.")

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to send image: {str(e)}")
            import traceback
            traceback.print_exc()


    def display_image_in_chat(self, pixmap=None, base64_data=None):
        """Display an image in the chat window"""
        from PyQt5.QtCore import QUrl
        from PyQt5.QtGui import QTextCursor, QImage
        from io import BytesIO
        from PIL import Image
        import base64
        
        try:
            print(f"[DEBUG] Attempting to display image - pixmap: {pixmap is not None}, base64: {base64_data is not None}")
            
            cursor = self.chat_window.textCursor()
            cursor.movePosition(QTextCursor.End)
            
            if pixmap is None and base64_data:
                # Decode base64 to image
                try:
                    print(f"[DEBUG] Decoding base64 image, length: {len(base64_data)}")
                    img_data = base64.b64decode(base64_data)
                    print(f"[DEBUG] Decoded image data size: {len(img_data)} bytes")
                    
                    # Try two approaches for maximum compatibility
                    try:
                        # Method 1: Direct QImage loading
                        img = QImage()
                        loaded = img.loadFromData(img_data)
                        print(f"[DEBUG] QImage direct load result: {loaded}")
                        
                        if not loaded:
                            # Method 2: Load with PIL and convert
                            print("[DEBUG] Trying PIL method")
                            buffer = BytesIO(img_data)
                            pil_img = Image.open(buffer)
                            pil_img = pil_img.convert("RGB")  
                            
                            # Save to new BytesIO with explicit format
                            new_buffer = BytesIO()
                            pil_img.save(new_buffer, format="JPEG")
                            new_buffer.seek(0)
                            
                            img = QImage()
                            loaded = img.loadFromData(new_buffer.getvalue())
                            print(f"[DEBUG] QImage via PIL load result: {loaded}")
                        
                        if loaded:
                            pixmap = QPixmap.fromImage(img)
                            pixmap = pixmap.scaled(400, 300, aspectRatioMode=Qt.KeepAspectRatio)
                            print(f"[DEBUG] Pixmap created: {not pixmap.isNull()}")
                        else:
                            print("[ERROR] Failed to load image data with both methods")
                            return
                            
                    except Exception as inner_e:
                        print(f"[ERROR] Inner error in image processing: {inner_e}")
                        import traceback
                        traceback.print_exc()
                        return
                        
                except Exception as e:
                    print(f"[ERROR] Error decoding image: {e}")
                    import traceback
                    traceback.print_exc()
                    return
            
            if pixmap and not pixmap.isNull():
                print("[DEBUG] Adding image to document")
                self.chat_window.document().addResource(
                    QTextDocument.ImageResource,
                    QUrl("image"),
                    pixmap
                )
                cursor.insertImage("image")
                cursor.insertBlock()
                self.chat_window.setTextCursor(cursor)
                print("[DEBUG] Image displayed successfully")
            else:
                print("[ERROR] No valid pixmap to display")
        except Exception as e:
            print(f"[ERROR] Error in display_image_in_chat: {e}")
            import traceback
            traceback.print_exc()


    def create_chat_page(self):
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        
        # Header with username and onion ID
        header_layout = QHBoxLayout()
        self.user_label = QLabel()
        self.user_label.setStyleSheet("font-weight: bold;")
        self.onion_id_label = QLabel()
        header_layout.addWidget(self.user_label)
        header_layout.addWidget(self.onion_id_label)
        
        # New chat section
        new_chat_layout = QHBoxLayout()
        recipient_label = QLabel("Recipient Onion ID:")
        self.recipient_input = QLineEdit()
        new_chat_button = QPushButton("Start Chat")
        new_chat_button.clicked.connect(self.start_new_chat)
        new_chat_layout.addWidget(recipient_label)
        new_chat_layout.addWidget(self.recipient_input)
        new_chat_layout.addWidget(new_chat_button)
        
        # Chat window
        self.chat_window = QTextEdit()
        self.chat_window.setReadOnly(True)
        
        # Message input
        message_layout = QHBoxLayout()
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(70)
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_message)
        
        # Add image button
        image_button = QPushButton("Send Image")
        image_button.clicked.connect(self.send_image)
        
        message_layout.addWidget(self.message_input)
        message_layout.addWidget(send_button)
        message_layout.addWidget(image_button)  # Add the image button
        
        # Logout button
        logout_button = QPushButton("Logout")
        logout_button.clicked.connect(self.handle_logout)
        
        chat_layout.addLayout(header_layout)
        chat_layout.addLayout(new_chat_layout)
        chat_layout.addWidget(self.chat_window)
        chat_layout.addLayout(message_layout)
        chat_layout.addWidget(logout_button)
        
        self.stacked_widget.addWidget(chat_widget)
    
    def update_status(self, message):
        self.status_bar.showMessage(message)

    
    
    def handle_login(self):
       

        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Login Error", "Please enter both username and password")
            return

        success, message = self.tor_dht_chat.login(username, password)
        if success:
            self.current_user = username
            self.user_label.setText(f"Logged in as: {username}")

            # Start Tor
            self.signals.status_update.emit("Starting Tor network connection...")
            if not self.tor_dht_chat.start_tor():
                QMessageBox.critical(self, "Error", "Failed to start Tor. Check the logs.")
                return

            self.signals.status_update.emit("Creating onion service...")
            onion_address = self.tor_dht_chat.create_onion_service(username)

            if not onion_address:
                QMessageBox.critical(self, "Error", "Failed to create onion service. Check the logs.")
                return

            # Check if a bootstrap node is available
            bootstrap_nodes = self.tor_dht_chat.get_bootstrap_nodes()

            self.signals.status_update.emit("Starting DHT network...")
            if not self.tor_dht_chat.start_dht_node(bootstrap_nodes=bootstrap_nodes):
                QMessageBox.critical(self, "Error", "Failed to start DHT node. Check the logs.")
                return

            # Update user's onion ID
            self.tor_dht_chat.users[username]["onion_id"] = onion_address
            self.tor_dht_chat.save_users()

            self.onion_id_label.setText(f"Your Onion ID: {onion_address}")

            # Start message checking thread
            self.running = True
            self.message_checker_thread = threading.Thread(target=self.check_messages, daemon=True)
            self.message_checker_thread.start()

            # Switch to chat page
            self.stacked_widget.setCurrentIndex(2)
            self.signals.status_update.emit("Ready to chat")
            QMessageBox.information(self, "Success", "Login successful")
        else:
            QMessageBox.warning(self, "Login Error", message)
    
    def handle_signup(self):
        username = self.signup_username_input.text()
        password = self.signup_password_input.text()
        confirm = self.confirm_password_input.text()
        
        if not username or not password or not confirm:
            QMessageBox.warning(self, "Signup Error", "Please fill in all fields")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "Signup Error", "Passwords do not match")
            return
        
        success, message = self.tor_dht_chat.signup(username, password)
        if success:
            QMessageBox.information(self, "Success", "Account created successfully")
            self.stacked_widget.setCurrentIndex(0)  # Back to login
        else:
            QMessageBox.warning(self, "Signup Error", message)
    
    def handle_logout(self):
        if self.current_user:
            self.signals.status_update.emit("Logging out...")
            self.running = False
            if self.message_checker_thread:
                self.message_checker_thread.join(1)
            
            self.tor_dht_chat.stop()
            self.current_user = None
            
            # Clear fields
            self.username_input.clear()
            self.password_input.clear()
            self.recipient_input.clear()
            self.message_input.clear()
            self.chat_window.clear()
            
            # Back to login page
            self.stacked_widget.setCurrentIndex(0)
            self.signals.status_update.emit("Ready")

    
    
    def start_new_chat(self):
        recipient = self.recipient_input.text().strip()
        if not recipient:
            QMessageBox.warning(self, "Error", "Please enter a recipient onion ID")
            return
        
        # self.current_recipient = recipient
        self.current_recipient = recipient  # Should be the known username from users.json

        self.chat_window.clear()
        self.chat_window.append(f"--- Starting chat with {recipient} ---")
    
    def send_message(self):
        if not hasattr(self, 'current_recipient') or not self.current_recipient:
            QMessageBox.warning(self, "Error", "Please select a recipient first")
            return
        
        message = self.message_input.toPlainText().strip()
        if not message:
            return
        
        try:
            self.signals.status_update.emit(f"Sending message to {self.current_recipient}...")
            
           
            if self.tor_dht_chat.store_obfuscated_message(
                self.current_recipient, 
                message, 
                self.current_user
            ):

                # Update chat window
                self.chat_window.append(f"You: {message}")
                self.message_input.clear()
                self.signals.status_update.emit("Message sent")
            else:
                QMessageBox.warning(self, "Error", "Failed to send message. DHT may be unavailable.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to send message: {str(e)}")
    
 
    def check_messages(self):
        while self.running:
            try:
                if self.current_user and self.tor_dht_chat.onion_address:
                    messages = self.tor_dht_chat.get_obfuscated_message(self.tor_dht_chat.onion_address)

                    if messages:
                        sender = messages["sender"]
                        is_image = messages.get("is_image", False)
                        content = messages["content"]

                        if is_image:
                            print(f"[DEBUG] Displaying received image from {sender}")
                            self.signals.message_received.emit(sender, json.dumps({
                                "is_image": True,
                                "content": content
                            }))
                        else:
                            self.signals.message_received.emit(sender, content)

            except Exception as e:
                print(f"[ERROR] Error checking messages: {e}")
            
            time.sleep(5)
    
 
    def update_chat_window(self, sender, content):
        try:
            # Check if the message is from the DHT
            if isinstance(content, dict):
                # Handle older message format
                is_image = content.get("is_image", False)
                actual_content = content.get("content", "")
                self.chat_window.append(f"{sender}: {'[Image]' if is_image else actual_content}")
                
                if is_image:
                    self.display_image_in_chat(base64_data=actual_content)
                return
            
            if isinstance(content, str):
                try:
                    import json
                    msg_data = json.loads(content)
                    if isinstance(msg_data, dict) and msg_data.get("is_image", False):
                        self.chat_window.append(f"{sender}: [Image]")
                        self.display_image_in_chat(base64_data=msg_data.get("content", ""))
                        return
                except json.JSONDecodeError:
                    pass  
            
            # Regular text message
            message = content
            is_image = False
            
            # Check if we need to parse the message object
            if isinstance(content, dict):
                message = content.get("content", "")
                is_image = content.get("is_image", False)
                
            self.chat_window.append(f"{sender}: {'[Image]' if is_image else message}")
            
            if is_image:
                try:
                    # Display the received image
                    self.display_image_in_chat(base64_data=message)
                except Exception as e:
                    print(f"[ERROR] Error displaying received image: {e}")
                    import traceback
                    traceback.print_exc()
        except Exception as e:
            print(f"[ERROR] Error in update_chat_window: {e}")
            import traceback
            traceback.print_exc()

def main():
    tor_path = "C:\\Users\\Lgnik\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"
    
    # Check if Tor exists
    if not os.path.exists(tor_path):
        print(f"Error: Tor executable not found at {tor_path}")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    chat_app = ChatGUI(tor_path)
    chat_app.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
