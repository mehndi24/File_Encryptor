# 🔐 Advanced File Encryptor  

A modern **file encryption & decryption desktop app** built with [Flet](https://flet.dev/) in Python.  
It supports multiple encryption methods (from beginner-friendly ciphers to secure Fernet encryption), has a sleek dark-themed UI, and maintains a detailed log of operations.  

---

## ✨ Features  
- 🎨 **Beautiful Dark UI** (Flet + custom purple theme).  
- 📁 **Multi-file selection** with file list preview.  
- 🔐 **4 encryption methods**:  
  - Caesar Cipher (shift-based substitution).  
  - ROT13 (simple substitution).  
  - XOR Cipher (password-based).  
  - Fernet (AES-based, secure).  
- 🔑 Password protection & Caesar shift options.  
- 📊 Real-time **progress bar & status updates**.  
- 📋 **Operation log** (saved in `encryption_log.json` + on-screen).  
- 📝 Text preview after decryption (for Caesar/ROT13).  

---

## 🚀 Getting Started  

### 1. Clone the repository  
git clone https://github.com/YourUsername/advanced-file-encryptor.git
cd advanced-file-encryptory


### 2. Install dependencies
Make sure you have Python 3.9+ installed, then run:
pip install flet cryptograph

### 3. Run the app
python En.py

## 🖼️ UI Preview
<img width="1271" height="721" alt="image" src="https://github.com/user-attachments/assets/d47d7e6f-361b-448d-acc4-9787dadd353c" />
<img width="1269" height="718" alt="image" src="https://github.com/user-attachments/assets/2348412f-9ea1-4022-bcf9-e75f58baef43" />
<img width="1269" height="715" alt="image" src="https://github.com/user-attachments/assets/1d841244-0eeb-4466-a778-6b9dd3f6a9c6" />
<img width="1272" height="715" alt="image" src="https://github.com/user-attachments/assets/b9efa431-2388-4e9a-86c6-0ced33ec1c40" />
<img width="1270" height="717" alt="image" src="https://github.com/user-attachments/assets/3d5b298e-7340-41a5-8f42-f0ebcc9c00e5" />
<img width="1277" height="723" alt="image" src="https://github.com/user-attachments/assets/649e6fe9-39b6-427d-adcd-87a300f06426" />
<img width="598" height="500" alt="image" src="https://github.com/user-attachments/assets/d68e5edf-67cb-4de5-943b-1e7f11286cc4" />

## 🛠️ Built With
~ Python
~ Flet : Modern Flutter-inspired Python UI framework.
~ cryptography : For Fernet encryption.
