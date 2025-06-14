import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import cv2
import numpy as np
from skimage.morphology import skeletonize
from PIL import Image, ImageTk
import cv2
import numpy as np
from skimage.morphology import skeletonize
from cryptography.fernet import Fernet
from scipy.spatial import cKDTree
import hashlib, base64
import os


def preprocess(image_path):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    blur = cv2.GaussianBlur(img, (5, 5), 0)
    _, thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    binary = thresh // 255
    skeleton = skeletonize(binary == 1)
    return skeleton.astype(np.uint8)


def get_minutiae_points(skel):
    minutiae = []
    rows, cols = skel.shape
    for x in range(1, rows - 1):
        for y in range(1, cols - 1):
            if skel[x, y] == 1:
                region = skel[x - 1 : x + 2, y - 1 : y + 2]
                count = np.sum(region) - 1
                if count == 1 or count == 3:
                    minutiae.append((x, y))
    return minutiae


def match_minutiae(ref_points, test_points):
    # distance-based comparison
    from scipy.spatial import distance_matrix
    import numpy as np

    if len(ref_points) == 0 or len(test_points) == 0:
        return 0.0

    ref = np.array(ref_points)
    test = np.array(test_points)

    dists = distance_matrix(ref, test)
    min_dists = dists.min(axis=1)

    avg_dist = np.mean(min_dists)
    normalized = max(0.0, 1.0 - avg_dist / 50.0)  # assumes max match radius ~50 pixels
    return normalized


def minutiae_to_key(minutiae):
    data = "".join(f"{x}-{y}" for x, y in sorted(minutiae))
    hash_digest = hashlib.sha256(data.encode()).digest()
    key = hashlib.sha256(hash_digest).digest()
    return Fernet(base64.urlsafe_b64encode(key[:32]))


# === File Operations ===


def encrypt_file(file_path, fingerprint_img, output_path):
    skel = preprocess(fingerprint_img)
    minutiae = get_minutiae_points(skel)
    fernet = minutiae_to_key(minutiae)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    with open(output_path, "wb") as f:
        f.write(encrypted)


def decrypt_file(encrypted_path, test_img, ref_img, output_path, threshold=0.6):
    skel_ref = preprocess(ref_img)
    min_ref = get_minutiae_points(skel_ref)

    skel_test = preprocess(test_img)
    min_test = get_minutiae_points(skel_test)

    similarity = match_minutiae(min_ref, min_test)

    if similarity >= threshold:
        try:
            fernet = minutiae_to_key(min_ref)
            with open(encrypted_path, "rb") as f:
                encrypted = f.read()
            decrypted = fernet.decrypt(encrypted)
            with open(output_path, "wb") as f:
                f.write(decrypted)
            return True, similarity
        except Exception as e:
            print("[ERROR] Decryption failed:", e)
            return False, similarity


class FingerprintApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Fingerprint Encryption")
        self.root.geometry("800x550")
        self.file_path = ""
        self.decrypt_fp = ""
        self.encrypted_file_path = ""
        self.reference_fp = "reference.jpg"  # assumed default

        self.build_gui()
        self.load_reference_image()

    def build_gui(self):
        # Buttons
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
from scipy.spatial import cKDTree
import hashlib, base64
import os


def preprocess(image_path):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    blur = cv2.GaussianBlur(img, (5, 5), 0)
    _, thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    binary = thresh // 255
    skeleton = skeletonize(binary == 1)
    return skeleton.astype(np.uint8)


def get_minutiae_points(skel):
    minutiae = []
    rows, cols = skel.shape
    for x in range(1, rows - 1):
        for y in range(1, cols - 1):
            if skel[x, y] == 1:
                region = skel[x - 1 : x + 2, y - 1 : y + 2]
                count = np.sum(region) - 1
                if count == 1 or count == 3:
                    minutiae.append((x, y))
    return minutiae


def match_minutiae(ref_points, test_points):
    # distance-based comparison
    from scipy.spatial import distance_matrix
    import numpy as np

    if len(ref_points) == 0 or len(test_points) == 0:
        return 0.0

    ref = np.array(ref_points)
    test = np.array(test_points)

    dists = distance_matrix(ref, test)
    min_dists = dists.min(axis=1)

    avg_dist = np.mean(min_dists)
    normalized = max(0.0, 1.0 - avg_dist / 50.0)  # assumes max match radius ~50 pixels
    return normalized


def minutiae_to_key(minutiae):
    data = "".join(f"{x}-{y}" for x, y in sorted(minutiae))
    hash_digest = hashlib.sha256(data.encode()).digest()
    key = hashlib.sha256(hash_digest).digest()
    return Fernet(base64.urlsafe_b64encode(key[:32]))


# === File Operations ===


def encrypt_file(file_path, fingerprint_img, output_path):
    skel = preprocess(fingerprint_img)
    minutiae = get_minutiae_points(skel)
    fernet = minutiae_to_key(minutiae)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    with open(output_path, "wb") as f:
        f.write(encrypted)


def decrypt_file(encrypted_path, test_img, ref_img, output_path, threshold=0.6):
    skel_ref = preprocess(ref_img)
    min_ref = get_minutiae_points(skel_ref)

    skel_test = preprocess(test_img)
    min_test = get_minutiae_points(skel_test)

    similarity = match_minutiae(min_ref, min_test)

    if similarity >= threshold:
        try:
            fernet = minutiae_to_key(min_ref)
            with open(encrypted_path, "rb") as f:
                encrypted = f.read()
            decrypted = fernet.decrypt(encrypted)
            with open(output_path, "wb") as f:
                f.write(decrypted)
            return True, similarity
        except Exception as e:
            print("[ERROR] Decryption failed:", e)
            return False, similarity


class FingerprintApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Fingerprint Encryption")
        self.root.geometry("800x550")
        self.file_path = ""
        self.decrypt_fp = ""
        self.encrypted_file_path = ""
        self.reference_fp = "reference.jpg"  # assumed default

        self.build_gui()
        self.load_reference_image()

    def build_gui(self):
        # Buttons
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Button(frame, text="Select File to Encrypt", command=self.select_file).grid(
            row=0, column=0, padx=5
        )
        tk.Button(frame, text="Select File to Encrypt", command=self.select_file).grid(
            row=0, column=0, padx=5
        )
        tk.Button(
            frame, text="Encrypt (Using Reference)", command=self.encrypt_by_reference
        ).grid(row=0, column=1, padx=5)
            frame, text="Encrypt (Using Reference)", command=self.encrypt_by_reference
        ).grid(row=0, column=1, padx=5)
        tk.Button(
            frame, text="Select Encrypted File", command=self.select_encrypted_file
        ).grid(row=1, column=0, padx=5)
            frame, text="Select Encrypted File", command=self.select_encrypted_file
        ).grid(row=1, column=0, padx=5)
        tk.Button(
            frame, text="Select Fingerprint to Decrypt", command=self.select_decrypt_fp
        ).grid(row=1, column=1, padx=5)
        tk.Button(frame, text="Decrypt", command=self.decrypt).grid(
            row=2, column=0, columnspan=2, pady=10
            frame, text="Select Fingerprint to Decrypt", command=self.select_decrypt_fp
        ).grid(row=1, column=1, padx=5)
        tk.Button(frame, text="Decrypt", command=self.decrypt).grid(
            row=2, column=0, columnspan=2, pady=10
        )

        # Image display
        self.img_frame = tk.Frame(self.root)
        self.img_frame.pack()

        # Image display
        self.img_frame = tk.Frame(self.root)
        self.img_frame.pack()

        tk.Label(self.img_frame, text="Reference").grid(row=0, column=0)
        tk.Label(self.img_frame, text="Test Fingerprint").grid(row=0, column=1)
        tk.Label(self.img_frame, text="Reference").grid(row=0, column=0)
        tk.Label(self.img_frame, text="Test Fingerprint").grid(row=0, column=1)

        self.ref_canvas = tk.Label(self.img_frame)
        self.ref_canvas.grid(row=1, column=0, padx=10)

        self.test_canvas = tk.Label(self.img_frame)
        self.test_canvas.grid(row=1, column=1, padx=10)
        self.ref_canvas = tk.Label(self.img_frame)
        self.ref_canvas.grid(row=1, column=0, padx=10)

        self.test_canvas = tk.Label(self.img_frame)
        self.test_canvas.grid(row=1, column=1, padx=10)

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            messagebox.showinfo("Selected", f"File: {self.file_path}")
    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            messagebox.showinfo("Selected", f"File: {self.file_path}")

    def encrypt_by_reference(self):
        if not self.file_path or not os.path.exists(self.reference_fp):
            messagebox.showerror("Error", "Missing file or reference.jpg")
    def encrypt_by_reference(self):
        if not self.file_path or not os.path.exists(self.reference_fp):
            messagebox.showerror("Error", "Missing file or reference.jpg")
            return
        out = filedialog.asksaveasfilename(defaultextension=".enc")
        encrypt_file(self.file_path, self.reference_fp, out)
        messagebox.showinfo("Encrypted", f"Saved to: {out}")

    def select_encrypted_file(self):
        self.encrypted_file_path = filedialog.askopenfilename()
        out = filedialog.asksaveasfilename(defaultextension=".enc")
        encrypt_file(self.file_path, self.reference_fp, out)
        messagebox.showinfo("Encrypted", f"Saved to: {out}")

    def select_encrypted_file(self):
        self.encrypted_file_path = filedialog.askopenfilename()

    def select_decrypt_fp(self):
        self.decrypt_fp = filedialog.askopenfilename()
        self.load_image(self.decrypt_fp, self.test_canvas)

    def load_reference_image(self):
        if os.path.exists(self.reference_fp):
            self.load_image(self.reference_fp, self.ref_canvas)

    def load_image(self, path, canvas):
        try:
            img = Image.open(path).resize((200, 200))
            img_tk = ImageTk.PhotoImage(img)
            canvas.image = img_tk  # prevent GC
            canvas.configure(image=img_tk)
    def select_decrypt_fp(self):
        self.decrypt_fp = filedialog.askopenfilename()
        self.load_image(self.decrypt_fp, self.test_canvas)

    def load_reference_image(self):
        if os.path.exists(self.reference_fp):
            self.load_image(self.reference_fp, self.ref_canvas)

    def load_image(self, path, canvas):
        try:
            img = Image.open(path).resize((200, 200))
            img_tk = ImageTk.PhotoImage(img)
            canvas.image = img_tk  # prevent GC
            canvas.configure(image=img_tk)
        except Exception as e:
            print("Image load failed:", e)

    def decrypt(self):
        if (
            not self.encrypted_file_path
            or not self.decrypt_fp
            or not os.path.exists(self.reference_fp)
        ):
            messagebox.showerror("Error", "Missing required file(s)")
            print("Image load failed:", e)

    def decrypt(self):
        if (
            not self.encrypted_file_path
            or not self.decrypt_fp
            or not os.path.exists(self.reference_fp)
        ):
            messagebox.showerror("Error", "Missing required file(s)")
            return
        out = filedialog.asksaveasfilename()
        success, score = decrypt_file(
            self.encrypted_file_path, self.decrypt_fp, self.reference_fp, out, 0.6
        )
        if success:
            messagebox.showinfo("Success", f"Decrypted!\nSimilarity: {score*100:.1f}%")
        out = filedialog.asksaveasfilename()
        success, score = decrypt_file(
            self.encrypted_file_path, self.decrypt_fp, self.reference_fp, out, 0.6
        )
        if success:
            messagebox.showinfo("Success", f"Decrypted!\nSimilarity: {score*100:.1f}%")
        else:
            messagebox.showerror("Failed", f"Similarity too low ({score*100:.1f}%)")
            messagebox.showerror("Failed", f"Similarity too low ({score*100:.1f}%)")


# Run it
# Run it
if __name__ == "__main__":
    root = tk.Tk()
    app = FingerprintApp(root)
    root.mainloop()

    root = tk.Tk()
    app = FingerprintApp(root)
    root.mainloop()