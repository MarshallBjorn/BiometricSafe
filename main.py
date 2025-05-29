import tkinter as tk
from tkinter import filedialog, messagebox
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from PIL import Image, ImageTk  # For image handling


# --- Biometric function simulation (replacing MegaMatcher) ---
def simulate_generate_template_from_image(image_path):
    """
    Simulates generating a fingerprint "template" from an image file.
    In a real application, this would involve calling a function from the MegaMatcher SDK.
    For simplification, the "template" will be the SHA-256 hash of the image file's content.
    Note: If you have pre-existing template files (e.g., .tnp from MegaMatcher),
    this function would be replaced by one that loads and processes that template file directly.
    """
    try:
        with open(image_path, "rb") as f:
            image_bytes = f.read()
        # Return the hash as the "template" - this is just a simulation
        return hashlib.sha256(image_bytes).digest()
    except Exception as e:
        messagebox.showerror("Simulation Error", f"Could not process image: {e}")
        return None


def simulate_compare_templates(template1_data, template2_data):
    """
    Simulates comparing two fingerprint "templates".
    In a real application, this would involve calling NFMatcher.Verify().
    For simplification, we directly compare the "template" data.
    """
    if template1_data is None or template2_data is None:
        return False
    return template1_data == template2_data


# --- Cryptographic functions ---
def derive_fernet_key(template_data):
    """
    Derives a Fernet key from template data (e.g., a hash).
    A Fernet key must be 32 bytes and URL-safe base64 encoded.
    """
    # We use SHA-256 of the template data, which yields 32 bytes - perfect for Fernet.
    sha256_hash = hashlib.sha256(template_data).digest()
    return base64.urlsafe_b64encode(sha256_hash)


def encrypt_file_operation(file_path, key, registration_template_data):
    """
    Encrypts a file using a Fernet key and saves the encrypted file
    along with the "template" used for registration.
    """
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as original_file:
            original_content = original_file.read()

        encrypted_content = fernet.encrypt(original_content)

        base_path, extension = os.path.splitext(file_path)
        secure_file_path = base_path + ".secure"
        # The template file stores the hash of the registration fingerprint image.
        template_file_path = (
            base_path + extension + ".template"
        )  # E.g., file.pdf.template

        with open(secure_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_content)

        with open(template_file_path, "wb") as template_file:
            template_file.write(
                registration_template_data
            )  # Save the hash of the registration image

        return secure_file_path, template_file_path
    except Exception as e:
        messagebox.showerror("Encryption Error", f"Could not encrypt file: {e}")
        return None, None


def decrypt_file_operation(secure_file_path, key):
    """
    Decrypts a .secure file using a Fernet key.
    """
    try:
        fernet = Fernet(key)
        with open(secure_file_path, "rb") as encrypted_file:
            encrypted_content = encrypted_file.read()

        decrypted_content = fernet.decrypt(encrypted_content)

        # Attempt to reconstruct the original filename.
        # base_path_secure is the original filename without the .secure extension.
        # e.g., if secure_file_path was "mydoc.pdf.secure", base_path_secure is "mydoc.pdf"
        base_path_secure = os.path.splitext(secure_file_path)[0]

        # The decrypted file will be saved with "decrypted_" prefix.
        output_filename = f"decrypted_{os.path.basename(base_path_secure)}"

        with open(output_filename, "wb") as decrypted_file:
            decrypted_file.write(decrypted_content)
        return output_filename
    except Exception as e:
        messagebox.showerror(
            "Decryption Error",
            f"Could not decrypt file: {e}. Key or file might be invalid.",
        )
        return None


# --- GUI Application (Tkinter) ---
class BiometricSafeApp:
    def __init__(self, master_window):
        self.master_window = master_window
        self.master_window.title("Biometric Safe")
        self.master_window.geometry("600x550")  # Increased height for image preview

        # Variables to store paths
        self.file_path_to_encrypt_var = tk.StringVar()
        self.fingerprint_image_encrypt_var = tk.StringVar()
        self.file_path_to_decrypt_var = tk.StringVar()
        self.fingerprint_image_decrypt_var = tk.StringVar()

        # --- Encryption Frame ---
        encryption_frame = tk.LabelFrame(
            master_window, text="Encrypt File", padx=10, pady=10
        )
        encryption_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(encryption_frame, text="File to encrypt:").grid(
            row=0, column=0, sticky="w", pady=2
        )
        tk.Entry(
            encryption_frame, textvariable=self.file_path_to_encrypt_var, width=50
        ).grid(row=0, column=1, pady=2)
        tk.Button(
            encryption_frame, text="Select File", command=self.select_file_to_encrypt
        ).grid(row=0, column=2, padx=5, pady=2)

        tk.Label(encryption_frame, text="Fingerprint image (registration):").grid(
            row=1, column=0, sticky="w", pady=2
        )
        tk.Entry(
            encryption_frame, textvariable=self.fingerprint_image_encrypt_var, width=50
        ).grid(row=1, column=1, pady=2)
        tk.Button(
            encryption_frame,
            text="Select Image",
            command=lambda: self.select_fingerprint_image(
                self.fingerprint_image_encrypt_var, "encrypt"
            ),
        ).grid(row=1, column=2, padx=5, pady=2)

        self.preview_encrypt_label = tk.Label(
            encryption_frame
        )  # Label for image preview
        self.preview_encrypt_label.grid(row=2, column=0, columnspan=3, pady=5)

        tk.Button(
            encryption_frame,
            text="Encrypt File",
            command=self.run_encryption_process,
            bg="lightblue",
            fg="black",
        ).grid(row=3, column=0, columnspan=3, pady=10)

        # --- Decryption Frame ---
        decryption_frame = tk.LabelFrame(
            master_window, text="Decrypt File", padx=10, pady=10
        )
        decryption_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(decryption_frame, text="File to decrypt (.secure):").grid(
            row=0, column=0, sticky="w", pady=2
        )
        tk.Entry(
            decryption_frame, textvariable=self.file_path_to_decrypt_var, width=50
        ).grid(row=0, column=1, pady=2)
        tk.Button(
            decryption_frame,
            text="Select File (.secure)",
            command=self.select_file_to_decrypt,
        ).grid(row=0, column=2, padx=5, pady=2)

        tk.Label(decryption_frame, text="Fingerprint image (verification):").grid(
            row=1, column=0, sticky="w", pady=2
        )
        tk.Entry(
            decryption_frame, textvariable=self.fingerprint_image_decrypt_var, width=50
        ).grid(row=1, column=1, pady=2)
        tk.Button(
            decryption_frame,
            text="Select Image",
            command=lambda: self.select_fingerprint_image(
                self.fingerprint_image_decrypt_var, "decrypt"
            ),
        ).grid(row=1, column=2, padx=5, pady=2)

        self.preview_decrypt_label = tk.Label(
            decryption_frame
        )  # Label for image preview
        self.preview_decrypt_label.grid(row=2, column=0, columnspan=3, pady=5)

        tk.Button(
            decryption_frame,
            text="Decrypt File",
            command=self.run_decryption_process,
            bg="lightgreen",
            fg="black",
        ).grid(row=3, column=0, columnspan=3, pady=10)

        # Status bar
        self.status_bar = tk.Label(
            master_window, text="Ready.", bd=1, relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        self.status_bar.config(text=message)
        self.master_window.update_idletasks()

    def select_file_to_encrypt(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if path:
            self.file_path_to_encrypt_var.set(path)
            self.update_status(
                f"Selected file for encryption: {os.path.basename(path)}"
            )

    def select_file_to_decrypt(self):
        path = filedialog.askopenfilename(
            title="Select .secure file to decrypt",
            filetypes=(("Secure files", "*.secure"), ("All files", "*.*")),
        )
        if path:
            self.file_path_to_decrypt_var.set(path)
            self.update_status(
                f"Selected file for decryption: {os.path.basename(path)}"
            )

    def select_fingerprint_image(self, path_variable, mode):
        path = filedialog.askopenfilename(
            title="Select fingerprint image",
            filetypes=(
                ("PNG images", "*.png"),
                ("JPG images", ("*.jpg", "*.jpeg")),
                ("BMP images", "*.bmp"),
                ("TIFF images", ("*.tif", "*.tiff")),
                ("All files", "*.*"),
            ),
        )

        if path:
            path_variable.set(path)
            self.display_image_preview(path, mode)
            self.update_status(f"Selected fingerprint image: {os.path.basename(path)}")

    def display_image_preview(self, image_path, mode):
        try:
            img = Image.open(image_path)
            img.thumbnail((100, 100))  # Resize image for preview
            photo_img = ImageTk.PhotoImage(img)

            if mode == "encrypt":
                self.preview_encrypt_label.config(image=photo_img)
                self.preview_encrypt_label.image = photo_img  # Keep a reference!
            elif mode == "decrypt":
                self.preview_decrypt_label.config(image=photo_img)
                self.preview_decrypt_label.image = photo_img  # Keep a reference!
        except Exception as e:
            messagebox.showwarning("Image Preview", f"Could not load preview: {e}")
            if mode == "encrypt":
                self.preview_encrypt_label.config(image=None)
            elif mode == "decrypt":
                self.preview_decrypt_label.config(image=None)

    def run_encryption_process(self):
        input_file = self.file_path_to_encrypt_var.get()
        registration_fingerprint_image = self.fingerprint_image_encrypt_var.get()

        if not input_file or not registration_fingerprint_image:
            messagebox.showerror(
                "Error", "Please select a file AND a fingerprint image for encryption."
            )
            return

        self.update_status("Generating fingerprint template (encryption)...")
        registration_template_data = simulate_generate_template_from_image(
            registration_fingerprint_image
        )

        if not registration_template_data:
            self.update_status("Error generating fingerprint template.")
            return

        self.update_status("Deriving encryption key...")
        encryption_key = derive_fernet_key(registration_template_data)

        self.update_status(f"Encrypting file: {os.path.basename(input_file)}...")
        created_secure_file, created_template_file = encrypt_file_operation(
            input_file, encryption_key, registration_template_data
        )

        if created_secure_file and created_template_file:
            messagebox.showinfo(
                "Success",
                f"File encrypted as: {os.path.basename(created_secure_file)}\n"
                f"Template saved as: {os.path.basename(created_template_file)}",
            )
            self.update_status("Encryption completed successfully.")
        else:
            self.update_status("Encryption failed.")

    def run_decryption_process(self):
        input_secure_file = self.file_path_to_decrypt_var.get()
        verification_fingerprint_image = self.fingerprint_image_decrypt_var.get()

        if not input_secure_file or not verification_fingerprint_image:
            messagebox.showerror(
                "Error",
                "Please select a .secure file AND a fingerprint image for decryption.",
            )
            return

        # Construct the path to the stored template file.
        # The template file is named like the original file, but with a .template extension.
        # e.g., if input_secure_file is "mydoc.pdf.secure",
        # the original file was "mydoc.pdf", so template is "mydoc.pdf.template".
        original_file_base_plus_ext = input_secure_file.replace(".secure", "")
        stored_template_file_path = original_file_base_plus_ext + ".template"

        if not os.path.exists(stored_template_file_path):
            messagebox.showerror(
                "Error",
                f"Template file not found: {os.path.basename(stored_template_file_path)}. "
                f"Ensure it's in the same directory as the .secure file "
                f"and named like the original file with a .template extension.",
            )
            self.update_status("Error: Template file missing.")
            return

        self.update_status("Loading stored fingerprint template...")
        try:
            with open(stored_template_file_path, "rb") as f:
                registered_template_data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Could not read template file: {e}")
            self.update_status("Error reading template file.")
            return

        self.update_status("Generating fingerprint template (verification)...")
        verification_template_data = simulate_generate_template_from_image(
            verification_fingerprint_image
        )

        if not verification_template_data:
            self.update_status("Error generating fingerprint template (verification).")
            return

        self.update_status("Comparing fingerprint templates...")
        templates_match = simulate_compare_templates(
            registered_template_data, verification_template_data
        )

        if templates_match:
            self.update_status("Fingerprints match. Deriving decryption key...")
            # Important: The decryption key must be derived from the ORIGINAL, stored template data!
            decryption_key = derive_fernet_key(registered_template_data)

            self.update_status(
                f"Decrypting file: {os.path.basename(input_secure_file)}..."
            )
            decrypted_file = decrypt_file_operation(input_secure_file, decryption_key)
            if decrypted_file:
                messagebox.showinfo(
                    "Success",
                    f"File decrypted successfully as: {os.path.basename(decrypted_file)}",
                )
                self.update_status("Decryption completed successfully.")
            else:
                self.update_status("Decryption failed.")
        else:
            messagebox.showerror(
                "Access Denied", "Fingerprints do not match. Cannot decrypt file."
            )
            self.update_status("Access denied: Fingerprints do not match.")


if __name__ == "__main__":
    # Firebase initialization (unused in this example, but placeholder for context)
    # const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
    # const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : null;
    # if (firebaseConfig) {
    #   // app = initializeApp(firebaseConfig);
    #   // db = getFirestore(app);
    #   // auth = getAuth(app);
    #   // setLogLevel('debug'); // Optional: for more detailed logs
    #   // ... sign in logic ...
    # }

    root_window = tk.Tk()
    app_instance = BiometricSafeApp(root_window)
    root_window.mainloop()
