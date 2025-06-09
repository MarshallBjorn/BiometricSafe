import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
from cryptography.fernet import Fernet
import hashlib
import base64
import os


def get_key_from_fingerprint(fingerprint_path):
    img = Image.open(fingerprint_path).convert("L")
    img = img.resize((128, 128))
    img_bytes = img.tobytes()
    hash_digest = hashlib.sha256(img_bytes).digest()
    return base64.urlsafe_b64encode(hash_digest[:32])  # Fernet key length


def encrypt_file():
    if not fingerprint_path or not file_path:
        messagebox.showerror(
            "Missing Input", "Please select both fingerprint and file."
        )
        return

    try:
        key = get_key_from_fingerprint(fingerprint_path)
        fernet = Fernet(key)

        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = fernet.encrypt(data)

        output_path = filedialog.asksaveasfilename(defaultextension=".safe")
        if output_path:
            with open(output_path, "wb") as f:
                f.write(encrypted)
            messagebox.showinfo("Success", "File encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error occured.", str(e))


def decrypt_file():
    if not fingerprint_path or not file_path:
        messagebox.showerror(
            "Missing Input", "Please select both fingerprint and encrypted file."
        )
        return

    try:
        key = get_key_from_fingerprint(fingerprint_path)
        fernet = Fernet(key)

        with open(file_path, "rb") as f:
            data = f.read()
        decrypted = fernet.decrypt(data)

        output_path = filedialog.asksaveasfilename(title="Save Decrypted File")
        if output_path:
            with open(output_path, "wb") as f:
                f.write(decrypted)
            messagebox.showinfo("Success", "File decrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error occured with decrypting file", str(e))


def select_fingerprint():
    global fingerprint_path
    fingerprint_path = filedialog.askopenfilename(
        filetypes=[("JPEG Files", "*.jpg *.jpeg")]
    )
    if fingerprint_path:
        fp_label.config(text=os.path.basename(fingerprint_path))


def select_file():
    global file_path
    file_path = filedialog.askopenfilename()
    if file_path:
        file_label.config(text=os.path.basename(file_path))


# GUI
app = tk.Tk()
app.title("Biometrical Safe")

fingerprint_path = ""
file_path = ""

tk.Label(app, text="1. Select Fingerprint (.jpg):").pack(pady=5)
tk.Button(app, text="Browse Fingerprint", command=select_fingerprint).pack()
fp_label = tk.Label(app, text="No fingerprint selected")
fp_label.pack()

tk.Label(app, text="2. Select File:").pack(pady=5)
tk.Button(app, text="Browse File", command=select_file).pack()
file_label = tk.Label(app, text="No file selected")
file_label.pack()


encrypt_btn = ttk.Button(app, text="🔐 Encrypt File", command=encrypt_file)
encrypt_btn.pack(pady=10, ipadx=10, ipady=5)

decrypt_btn = ttk.Button(app, text="🔓 Decrypt File", command=decrypt_file)
decrypt_btn.pack(pady=5, ipadx=10, ipady=5)


app.mainloop()
