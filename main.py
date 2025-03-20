import re
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import os
import math
import random
import string

# Constants for colors
COLOR_WEAK = "#FF6B6B"  # Red
COLOR_MODERATE = "#FFD166"  # Yellow
COLOR_STRONG = "#06D6A0"  # Green
COLOR_VERY_STRONG = "#4CAF50"  # Dark Green
COLOR_DEFAULT = "#FFFFFF"  # White
COLOR_BACKGROUND = "#F0F0F0"  # Light Gray
BUTTON_COLOR = "#4CAF50"  # Green
BUTTON_HOVER_COLOR = "#45a049"  # Darker Green
BUTTON_ACTIVE_COLOR = "#3d8b40"  # Even Darker Green

def load_common_passwords(file_path="common_passwords.txt"):
    """
    Load a list of common passwords from a file.
    """
    try:
        with open(file_path, "r") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        print(f"Warning: Common passwords file '{file_path}' not found.")
        return set()

def calculate_entropy(password):
    """
    Calculate the entropy of a password.
    """
    if not password:
        return 0
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset_size += 32
    return len(password) * math.log2(charset_size) if charset_size else 0

def hash_password(password):
    """
    Hash the password using SHA-256.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def generate_strong_password(length=16):
    """
    Generate a strong password with a mix of uppercase, lowercase, numbers, and special characters.
    """
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def check_password_history(password, history_file="password_history.txt"):
    """
    Check if the password has been used before.
    """
    if not os.path.exists(history_file):
        return False
    with open(history_file, "r") as file:
        hashed_passwords = set(line.strip() for line in file)
    return hash_password(password) in hashed_passwords

def update_password_history(password, history_file="password_history.txt"):
    """
    Update the password history file with the new password.
    """
    with open(history_file, "a") as file:
        file.write(hash_password(password) + "\n")

def check_password_strength(password, common_passwords):
    """
    Check the strength of a password and provide feedback.
    """
    strength = 0
    feedback = []

    # Check password length
    if len(password) >= 12:
        strength += 1
    else:
        feedback.append("Password should be at least 12 characters long.")

    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one uppercase letter.")

    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one lowercase letter.")

    # Check for numbers
    if re.search(r"\d", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one number.")

    # Check for special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one special character.")

    # Check if password is common
    if password.lower() in common_passwords:
        strength = 0
        feedback.append("Password is too common. Choose a more unique password.")

    # Check password history
    if check_password_history(password):
        strength = 0
        feedback.append("Password has been used before. Choose a new password.")

    # Calculate entropy
    entropy = calculate_entropy(password)
    feedback.append(f"Password entropy: {entropy:.2f} bits")

    # Determine strength level and color
    if strength == 5:
        strength_level = "Very Strong"
        strength_color = COLOR_VERY_STRONG
    elif strength >= 3:
        strength_level = "Strong"
        strength_color = COLOR_STRONG
    elif strength >= 1:
        strength_level = "Moderate"
        strength_color = COLOR_MODERATE
    else:
        strength_level = "Very Weak"
        strength_color = COLOR_WEAK

    return strength_level, strength_color, feedback

class PasswordStrengthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("500x450")
        self.root.resizable(False, False)
        self.root.configure(bg=COLOR_BACKGROUND)

        self.common_passwords = load_common_passwords()

        # Configure styles
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("Arial", 12), background=COLOR_BACKGROUND)
        self.style.configure("TEntry", font=("Arial", 12))

        self.create_widgets()

    def create_widgets(self):
        # Main container
        container = ttk.Frame(self.root, padding="20")
        container.pack(fill=tk.BOTH, expand=True)

        # Password Entry
        self.label_password = ttk.Label(container, text="Enter Password:")
        self.label_password.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))

        # Frame for password entry and show/hide button
        self.entry_frame = ttk.Frame(container)
        self.entry_frame.grid(row=1, column=0, sticky=tk.W, pady=(0, 10))

        self.entry_password = ttk.Entry(self.entry_frame, show="*", width=25)
        self.entry_password.pack(side=tk.LEFT)

        # Show/Hide Button
        self.show_hide_button = tk.Button(
            self.entry_frame,
            text="👁️",
            bg=COLOR_BACKGROUND,
            fg="black",
            font=("Arial", 10),
            relief=tk.FLAT,
            bd=0,
            command=self.toggle_password_visibility
        )
        self.show_hide_button.pack(side=tk.LEFT, padx=5)

        # Check Button
        self.button_check = tk.Button(
            container,
            text="Check Strength",
            bg=BUTTON_COLOR,
            fg="white",
            font=("Arial", 12, "bold"),
            relief=tk.FLAT,
            activebackground=BUTTON_ACTIVE_COLOR,
            activeforeground="white",
            bd=0,
            padx=20,
            pady=10,
            command=self.check_strength
        )
        self.button_check.grid(row=2, column=0, sticky=tk.W, pady=(0, 10))
        self.button_check.bind("<Enter>", lambda e: self.button_check.config(bg=BUTTON_HOVER_COLOR))
        self.button_check.bind("<Leave>", lambda e: self.button_check.config(bg=BUTTON_COLOR))

        # Generate Password Button
        self.button_generate = tk.Button(
            container,
            text="Generate Strong Password",
            bg=BUTTON_COLOR,
            fg="white",
            font=("Arial", 12, "bold"),
            relief=tk.FLAT,
            activebackground=BUTTON_ACTIVE_COLOR,
            activeforeground="white",
            bd=0,
            padx=20,
            pady=10,
            command=self.generate_password
        )
        self.button_generate.grid(row=3, column=0, sticky=tk.W, pady=(0, 10))
        self.button_generate.bind("<Enter>", lambda e: self.button_generate.config(bg=BUTTON_HOVER_COLOR))
        self.button_generate.bind("<Leave>", lambda e: self.button_generate.config(bg=BUTTON_COLOR))

        # Strength Label
        self.label_strength = ttk.Label(container, text="Strength: None", font=("Arial", 14, "bold"))
        self.label_strength.grid(row=4, column=0, sticky=tk.W, pady=(10, 5))

        # Feedback Text
        self.feedback_text = tk.Text(container, height=6, width=50, wrap=tk.WORD, state=tk.DISABLED, font=("Arial", 10))
        self.feedback_text.grid(row=5, column=0, sticky=tk.W, pady=(0, 10))

    def toggle_password_visibility(self):
        """
        Toggle between showing and hiding the password.
        """
        if self.entry_password.cget("show") == "*":
            self.entry_password.config(show="")
            self.show_hide_button.config(text="👁️")
        else:
            self.entry_password.config(show="*")
            self.show_hide_button.config(text="👁️")

    def check_strength(self):
        password = self.entry_password.get()
        strength_level, strength_color, feedback = check_password_strength(password, self.common_passwords)

        # Update strength label with color
        self.label_strength.config(text=f"Strength: {strength_level}", foreground=strength_color)

        # Update feedback text
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        if feedback:
            for message in feedback:
                self.feedback_text.insert(tk.END, f"- {message}\n")
        else:
            self.feedback_text.insert(tk.END, "Password meets all strength requirements.")
        self.feedback_text.config(state=tk.DISABLED)

        # Update password history
        update_password_history(password)

    def generate_password(self):
        password = generate_strong_password()
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, password)
        self.check_strength()

    def realtime_feedback(self, event):
        password = self.entry_password.get()
        strength_level, strength_color, feedback = check_password_strength(password, self.common_passwords)

        # Update strength label with color
        self.label_strength.config(text=f"Strength: {strength_level}", foreground=strength_color)

        # Update feedback text
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        if feedback:
            for message in feedback:
                self.feedback_text.insert(tk.END, f"- {message}\n")
        else:
            self.feedback_text.insert(tk.END, "Password meets all strength requirements.")
        self.feedback_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthApp(root)
    root.mainloop()