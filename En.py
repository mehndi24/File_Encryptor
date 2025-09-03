import flet as ft
import os
import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from pathlib import Path
import json
import threading
import time

class EncryptionApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.selected_files = []
        self.setup_page()
        self.setup_ui()
        
    def setup_page(self):
        self.page.title = "Advanced File Encryptor"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.window_width = 900
        self.page.window_height = 800
        self.page.window_resizable = True  # Make it resizable
        self.page.bgcolor = "#1a0f2e"
        self.page.scroll = ft.ScrollMode.AUTO  # Make page scrollable
        
        # Custom purple theme
        self.page.theme = ft.Theme(
            color_scheme_seed="#8B5CF6",
            use_material3=True
        )
        
    def setup_ui(self):
        # Title
        title = ft.Text(
            "🔐 Advanced File Encryptor",
            size=32,
            weight=ft.FontWeight.BOLD,
            color="#A855F7",
            text_align=ft.TextAlign.CENTER
        )
        
        # Encryption method selection
        self.encryption_method = ft.Dropdown(
            label="Encryption Method",
            options=[
                ft.dropdown.Option("caesar", "Caesar Cipher"),
                ft.dropdown.Option("rot13", "ROT13"),
                ft.dropdown.Option("fernet", "Fernet (Secure)"),
                ft.dropdown.Option("xor", "XOR Cipher")
            ],
            value="fernet",
            bgcolor="#2D1B69",
            border_color="#8B5CF6",
            color="#FFFFFF",
            width=300
        )
        
        # File selection
        self.file_picker = ft.FilePicker(
            on_result=self.on_files_selected
        )
        self.page.overlay.append(self.file_picker)
        
        self.select_files_btn = ft.ElevatedButton(
            "📁 Select Files",
            on_click=lambda _: self.file_picker.pick_files(
                allow_multiple=True,
                allowed_extensions=["txt", "csv", "json", "py", "md", "log"]
            ),
            bgcolor="#8B5CF6",
            color="white",
            width=200
        )
        
        # Selected files display
        self.files_list = ft.Column(
            height=150,
            scroll=ft.ScrollMode.AUTO,
            auto_scroll=True
        )
        
        self.files_container = ft.Container(
            content=ft.Column([
                ft.Text("Selected Files:", size=14, color="#A855F7", weight=ft.FontWeight.BOLD),
                ft.Container(
                    content=self.files_list,
                    bgcolor="#1F2937",
                    border_radius=8,
                    padding=10,
                    width=500,
                    height=150
                )
            ]),
            margin=ft.margin.only(top=10)
        )
        
        # Password input
        self.password_field = ft.TextField(
            label="Password/Key",
            password=True,
            can_reveal_password=True,
            bgcolor="#2D1B69",
            border_color="#8B5CF6",
            color="#FFFFFF",
            width=300
        )
        
        # Caesar cipher shift (only shown when Caesar is selected)
        self.shift_field = ft.TextField(
            label="Caesar Shift (1-25)",
            value="3",
            bgcolor="#2D1B69",
            border_color="#8B5CF6",
            color="#FFFFFF",
            width=150,
            visible=False
        )
        
        # Action buttons
        self.encrypt_btn = ft.ElevatedButton(
            "🔒 Encrypt Files",
            on_click=self.encrypt_files,
            bgcolor="#059669",
            color="white",
            width=200
        )
        
        self.decrypt_btn = ft.ElevatedButton(
            "🔓 Decrypt Files",
            on_click=self.decrypt_files,
            bgcolor="#DC2626",
            color="white",
            width=200
        )
        
        # Progress and status
        self.progress_bar = ft.ProgressBar(
            width=500,
            color="#8B5CF6",
            bgcolor="#2D1B69",
            visible=False
        )
        
        self.status_text = ft.Text(
            "",
            size=16,
            color="#A855F7",
            text_align=ft.TextAlign.CENTER
        )
        
        # Log display - Make it smaller but more visible
        self.log_text = ft.Text(
            "No operations yet...",
            size=11,
            color="#D1D5DB",
            selectable=True
        )
        
        self.log_scroll = ft.Column(
            controls=[self.log_text],
            scroll=ft.ScrollMode.ALWAYS,
            auto_scroll=True,
            height=120,
            width=480
        )
        
        self.log_container = ft.Container(
            content=ft.Column([
                ft.Text("📋 Operation Log", size=16, weight=ft.FontWeight.BOLD, color="#A855F7"),
                ft.Container(
                    content=self.log_scroll,
                    bgcolor="#1F2937",
                    border_radius=8,
                    padding=8,
                    width=500,
                    height=130,
                    border=ft.border.all(1, "#374151")
                )
            ]),
            margin=ft.margin.only(top=15)
        )
        
        # Add event listener for encryption method change
        self.encryption_method.on_change = self.on_method_change
        
        # Layout - Make the whole app scrollable
        main_column = ft.Column([
            ft.Container(title, alignment=ft.alignment.center, margin=ft.margin.only(bottom=20)),
            ft.Row([self.encryption_method, self.shift_field], alignment=ft.MainAxisAlignment.CENTER),
            ft.Container(height=20),
            ft.Row([self.select_files_btn], alignment=ft.MainAxisAlignment.CENTER),
            self.files_container,
            ft.Container(height=10),
            ft.Row([self.password_field], alignment=ft.MainAxisAlignment.CENTER),
            ft.Container(height=20),
            ft.Row([self.encrypt_btn, self.decrypt_btn], alignment=ft.MainAxisAlignment.CENTER, spacing=20),
            ft.Container(height=20),
            ft.Column([
                self.progress_bar,
                self.status_text
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            self.log_container,
            ft.Container(height=50)  # Add some bottom padding
        ], 
        alignment=ft.MainAxisAlignment.START, 
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        scroll=ft.ScrollMode.AUTO,  # Make the whole column scrollable
        expand=True
        )
        
        self.page.add(main_column)
        
        # Load existing log
        self.load_log()
        
    def on_method_change(self, e):
        if self.encryption_method.value == "caesar":
            self.shift_field.visible = True
            self.password_field.visible = False
        else:
            self.shift_field.visible = False
            self.password_field.visible = True
        self.page.update()
        
    def on_files_selected(self, e: ft.FilePickerResultEvent):
        if e.files:
            self.selected_files = [file.path for file in e.files]
            self.files_list.controls.clear()
            
            for file_path in self.selected_files:
                file_name = os.path.basename(file_path)
                file_tile = ft.ListTile(
                    leading=ft.Icon(ft.Icons.INSERT_DRIVE_FILE, color="#8B5CF6"),
                    title=ft.Text(file_name, color="#FFFFFF", size=12),
                    subtitle=ft.Text(file_path, color="#9CA3AF", size=10)
                )
                self.files_list.controls.append(file_tile)
            
            self.page.update()
        
    def caesar_cipher(self, text, shift, decrypt=False):
        if decrypt:
            shift = -shift
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def rot13_cipher(self, text):
        # Manual ROT13 implementation since encode('rot13') might not work in all Python versions
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def xor_cipher(self, data, key):
        key_bytes = key.encode('utf-8')
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(result)
    
    def generate_fernet_key(self, password):
        # Derive key from password using SHA256
        key = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(key)
    
    def save_key_to_file(self, key, filename):
        key_file = f"{filename}.key"
        with open(key_file, 'wb') as f:
            f.write(key)
        return key_file
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file for verification"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def log_operation(self, operation, files, method, status):
        """Log operations to file"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "files": files,
            "method": method,
            "status": status
        }
        
        log_file = "encryption_log.json"
        logs = []
        
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            except:
                logs = []
        
        logs.append(log_entry)
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
        
        self.update_log_display()
    
    def load_log(self):
        """Load and display existing log"""
        self.update_log_display()
    
    def update_log_display(self):
        """Update the log display"""
        log_file = "encryption_log.json"
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
                
                log_text = ""
                for log in logs[-10:]:  # Show last 10 entries
                    timestamp = datetime.fromisoformat(log['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                    log_text += f"[{timestamp}] {log['operation']} - {log['method']} - {log['status']}\n"
                    for file in log['files']:
                        log_text += f"  📄 {os.path.basename(file)}\n"
                    log_text += "\n"
                
                if not log_text:
                    log_text = "No operations yet..."
                
                self.log_text.value = log_text
                self.page.update()
            except Exception as e:
                self.log_text.value = f"Error loading log: {str(e)}"
                self.page.update()
        else:
            self.log_text.value = "No operations yet..."
            self.page.update()
    
    def show_progress(self, show=True):
        self.progress_bar.visible = show
        self.page.update()
    
    def update_status(self, message):
        self.status_text.value = message
        self.page.update()
    
    def process_files(self, operation):
        """Process files in a separate thread"""
        def worker():
            try:
                if not self.selected_files:
                    self.update_status("❌ Please select files first!")
                    return
                
                method = self.encryption_method.value
                
                if method == "caesar":
                    try:
                        shift = int(self.shift_field.value)
                        if not (1 <= shift <= 25):
                            raise ValueError
                    except ValueError:
                        self.update_status("❌ Please enter a valid shift (1-25)")
                        return
                elif method != "rot13":
                    if not self.password_field.value:
                        self.update_status("❌ Please enter a password!")
                        return
                
                self.show_progress(True)
                processed_files = []
                failed_files = []
                
                for i, file_path in enumerate(self.selected_files):
                    try:
                        self.update_status(f"📝 Processing {os.path.basename(file_path)}...")
                        
                        # Read file
                        if operation == "encrypt":
                            with open(file_path, 'rb') as f:
                                file_data = f.read()
                        else:
                            # For decryption, read as binary
                            with open(file_path, 'rb') as f:
                                file_data = f.read()
                        
                        if operation == "encrypt":
                            processed_data = self.encrypt_data(file_data, method)
                            suffix = "_encrypted"
                        else:
                            processed_data = self.decrypt_data(file_data, method)
                            suffix = "_decrypted"
                        
                        # Save processed file
                        file_path_obj = Path(file_path)
                        output_path = file_path_obj.parent / f"{file_path_obj.stem}{suffix}{file_path_obj.suffix}"
                        
                        with open(output_path, 'wb') as f:
                            f.write(processed_data)
                        
                        # For decryption, show a preview if it's text
                        if operation == "decrypt" and method in ["caesar", "rot13"]:
                            try:
                                preview = processed_data.decode('utf-8')[:100]
                                if len(processed_data.decode('utf-8')) > 100:
                                    preview += "..."
                                print(f"✅ Decrypted preview of {os.path.basename(output_path)}: {preview}")
                            except:
                                print(f"✅ Decrypted {os.path.basename(output_path)} (binary content)")
                        
                        processed_files.append(str(output_path))
                        
                        # Update progress
                        progress = (i + 1) / len(self.selected_files)
                        self.progress_bar.value = progress
                        self.page.update()
                        
                    except Exception as e:
                        failed_files.append((file_path, str(e)))
                
                # Final status
                if processed_files and not failed_files:
                    status = "✅ All files processed successfully!"
                    log_status = "SUCCESS"
                elif processed_files and failed_files:
                    status = f"⚠️ {len(processed_files)} files processed, {len(failed_files)} failed"
                    log_status = "PARTIAL_SUCCESS"
                else:
                    status = "❌ All files failed to process"
                    log_status = "FAILED"
                
                self.update_status(status)
                
                # Log the operation
                all_files = [f for f, _ in failed_files] + processed_files
                self.log_operation(operation.upper(), all_files, method, log_status)
                
                # Show detailed results
                if failed_files:
                    error_msg = "\\n".join([f"{os.path.basename(f)}: {e}" for f, e in failed_files])
                    # Create a dialog for errors since snack_bar might not be available
                    error_dialog = ft.AlertDialog(
                        title=ft.Text("❌ Errors Occurred"),
                        content=ft.Text(error_msg, color="#DC2626"),
                        actions=[ft.TextButton("OK", on_click=lambda e: self.page.close(error_dialog))]
                    )
                    self.page.open(error_dialog)
                
            except Exception as e:
                self.update_status(f"❌ Error: {str(e)}")
                self.log_operation(operation.upper(), self.selected_files, method, "ERROR")
            finally:
                self.show_progress(False)
        
        threading.Thread(target=worker, daemon=True).start()
    
    def encrypt_data(self, data, method):
        if method == "caesar":
            shift = int(self.shift_field.value)
            # Try to decode as text, if it fails, handle as binary
            try:
                text = data.decode('utf-8')
                encrypted_text = self.caesar_cipher(text, shift)
                return encrypted_text.encode('utf-8')
            except UnicodeDecodeError:
                # Handle binary files by converting to base64 first
                import base64
                text = base64.b64encode(data).decode('ascii')
                encrypted_text = self.caesar_cipher(text, shift)
                return encrypted_text.encode('utf-8')
        
        elif method == "rot13":
            try:
                text = data.decode('utf-8')
                encrypted_text = self.rot13_cipher(text)
                return encrypted_text.encode('utf-8')
            except UnicodeDecodeError:
                import base64
                text = base64.b64encode(data).decode('ascii')
                encrypted_text = self.rot13_cipher(text)
                return encrypted_text.encode('utf-8')
        
        elif method == "fernet":
            password = self.password_field.value
            key = self.generate_fernet_key(password)
            fernet = Fernet(key)
            return fernet.encrypt(data)
        
        elif method == "xor":
            password = self.password_field.value
            return self.xor_cipher(data, password)
    
    def decrypt_data(self, data, method):
        if method == "caesar":
            shift = int(self.shift_field.value)
            try:
                text = data.decode('utf-8')
                # Check if this looks like base64 encoded data
                if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text.replace('\n', '').replace('\r', '')):
                    try:
                        # Decrypt the text first, then decode from base64
                        decrypted_text = self.caesar_cipher(text, shift, decrypt=True)
                        import base64
                        return base64.b64decode(decrypted_text.encode('ascii'))
                    except:
                        pass
                # Regular text decryption
                decrypted_text = self.caesar_cipher(text, shift, decrypt=True)
                return decrypted_text.encode('utf-8')
            except UnicodeDecodeError:
                raise Exception("Cannot decrypt binary data with Caesar cipher")
        
        elif method == "rot13":
            try:
                text = data.decode('utf-8')
                # ROT13 is its own inverse, so we use the same function
                if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text.replace('\n', '').replace('\r', '')):
                    try:
                        decrypted_text = self.rot13_cipher(text)
                        import base64
                        return base64.b64decode(decrypted_text.encode('ascii'))
                    except:
                        pass
                decrypted_text = self.rot13_cipher(text)
                return decrypted_text.encode('utf-8')
            except UnicodeDecodeError:
                raise Exception("Cannot decrypt binary data with ROT13")
        
        elif method == "fernet":
            password = self.password_field.value
            key = self.generate_fernet_key(password)
            fernet = Fernet(key)
            return fernet.decrypt(data)
        
        elif method == "xor":
            password = self.password_field.value
            return self.xor_cipher(data, password)
    
    def encrypt_files(self, e):
        self.process_files("encrypt")
    
    def decrypt_files(self, e):
        self.process_files("decrypt")

def main(page: ft.Page):
    app = EncryptionApp(page)

if __name__ == "__main__":
    ft.app(target=main)