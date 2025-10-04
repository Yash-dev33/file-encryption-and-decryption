"""
Secure File Encryption GUI Application - Rufus Style
Professional Windows-style interface for file encryption and decryption.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path
from typing import List
from file_handler import FileHandler
from crypto_engine import CryptoEngine
from config_manager import ConfigManager


class RufusStyleGUI:
    """
    Rufus-style GUI application for file encryption/decryption.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption v1.0")
        
        # Window size - larger
        self.window_width = 310
        self.window_width_expanded = 545  # Width when log is shown
        self.window_height = 630 # Reduced from 750 to fit content better
        self.window_height_expanded = 700  # Height when log is shown
        
        # Center window on screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - self.window_width) // 2
        y = (screen_height - self.window_height) // 2
        self.root.geometry(f"{self.window_width}x{self.window_height}+{x}+{y}")
        self.root.resizable(False, False)
        
        # Variables
        self.operation_var = tk.StringVar(value="encrypt")
        self.algorithm_var = tk.StringVar(value="AES-256-GCM")
        self.delete_original_var = tk.BooleanVar(value=False)
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_log_var = tk.BooleanVar(value=False)
        
        # File list
        self.selected_files = []
        self.config = ConfigManager()
        
        # Colors - Windows style
        self.colors = {
            'bg': '#f0f0f0',
            'white': '#ffffff',
            'border': '#ababab',
            'accent': '#0078d7',
            'accent_hover': '#1a86da',
            'text': '#000000',
            'button': '#e1e1e1',
            'button_hover': '#e5f1fb',
            'link': '#0078d7'
        }
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])
        
        # Configure ttk styles
        self.configure_styles()
        
        # Build UI
        self.build_ui()
    
    def configure_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use('vista' if 'vista' in style.theme_names() else 'clam')
        
        # Frame styles
        style.configure('TFrame', background=self.colors['bg'])
        
        # LabelFrame styles
        style.configure('TLabelframe', background=self.colors['white'],
                       borderwidth=1, relief='solid')
        style.configure('TLabelframe.Label', background=self.colors['white'],
                       foreground=self.colors['text'],
                       font=('Segoe UI', 9, 'bold'))
    
    def build_ui(self):
        """Build the user interface."""
        # Main content frame
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        row = 0
        
        # Operation section
        self.build_operation_section(main_frame, row)
        row += 1
        
        # File section
        self.build_file_section(main_frame, row)
        row += 1
        
        # Encryption options
        self.build_crypto_section(main_frame, row)
        row += 1
        
        # Advanced options (collapsible)
        self.build_advanced_section(main_frame, row)
        row += 1
        
        # Status section
        self.build_status_section(main_frame, row)
        row += 1
        
        # Spacer
        tk.Frame(main_frame, height=10, bg=self.colors['bg']).grid(row=row, column=0)
        row += 1
        
        # Action buttons
        self.build_action_buttons(main_frame, row)
    
    def build_operation_section(self, parent, row):
        """Build operation selection section."""
        frame = ttk.LabelFrame(parent, text="Operation", padding="10")
        frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        btn_frame = tk.Frame(frame, bg=self.colors['white'])
        btn_frame.pack(fill=tk.X)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        
        # Encrypt button
        self.encrypt_btn = tk.Button(btn_frame, text="Encrypt Files",
                                     command=lambda: self.set_operation("encrypt"),
                                     bg=self.colors['accent'], fg='white',
                                     activebackground=self.colors['accent_hover'],
                                     activeforeground='white',
                                     relief='solid', borderwidth=1,
                                     font=('Segoe UI', 9),
                                     cursor='hand2')
        self.encrypt_btn.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 3), pady=5)
        
        # Decrypt button
        self.decrypt_btn = tk.Button(btn_frame, text="Decrypt Files",
                                     command=lambda: self.set_operation("decrypt"),
                                     bg=self.colors['button'], fg=self.colors['text'],
                                     activebackground=self.colors['button_hover'],
                                     activeforeground=self.colors['text'],
                                     relief='solid', borderwidth=1,
                                     font=('Segoe UI', 9),
                                     cursor='hand2')
        self.decrypt_btn.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(3, 0), pady=5)
    
    def build_file_section(self, parent, row):
        """Build file selection section."""
        frame = ttk.LabelFrame(parent, text="Files", padding="10")
        frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        # File listbox
        listbox_frame = tk.Frame(frame, bg=self.colors['white'], relief='solid', borderwidth=1)
        listbox_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_listbox = tk.Listbox(listbox_frame, height=5,
                                       bg=self.colors['white'],
                                       fg=self.colors['text'],
                                       font=('Segoe UI', 9),
                                       relief='flat',
                                       selectbackground=self.colors['accent'],
                                       selectforeground='white',
                                       yscrollcommand=scrollbar.set)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_listbox.yview)
        
        # Buttons
        btn_frame = tk.Frame(frame, bg=self.colors['white'])
        btn_frame.pack(fill=tk.X)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        
        add_btn = tk.Button(btn_frame, text="Add Files...",
                           command=self.add_files,
                           bg=self.colors['button'], fg=self.colors['text'],
                           activebackground=self.colors['button_hover'],
                           relief='solid', borderwidth=1,
                           font=('Segoe UI', 9),
                           cursor='hand2')
        add_btn.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 3))
        
        clear_btn = tk.Button(btn_frame, text="Clear",
                             command=self.clear_files,
                             bg=self.colors['button'], fg=self.colors['text'],
                             activebackground=self.colors['button_hover'],
                             relief='solid', borderwidth=1,
                             font=('Segoe UI', 9),
                             cursor='hand2')
        clear_btn.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(3, 0))
    
    def build_crypto_section(self, parent, row):
        """Build encryption options section."""
        frame = ttk.LabelFrame(parent, text="Encryption Options", padding="10")
        frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        inner_frame = tk.Frame(frame, bg=self.colors['white'])
        inner_frame.pack(fill=tk.X)
        
        # Algorithm
        algo_frame = tk.Frame(inner_frame, bg=self.colors['white'])
        algo_frame.pack(fill=tk.X, pady=(0, 8))
        
        tk.Label(algo_frame, text="Algorithm:", bg=self.colors['white'],
                fg=self.colors['text'], font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 5))
        
        self.algorithm_combo = ttk.Combobox(algo_frame, textvariable=self.algorithm_var,
                                           state='readonly', width=20,
                                           font=('Segoe UI', 9))
        self.algorithm_combo['values'] = list(CryptoEngine.ALGORITHMS.keys())
        self.algorithm_combo.pack(side=tk.LEFT)
        
        # Password
        pwd_frame = tk.Frame(inner_frame, bg=self.colors['white'])
        pwd_frame.pack(fill=tk.X, pady=(0, 8))
        
        tk.Label(pwd_frame, text="Password:", bg=self.colors['white'],
                fg=self.colors['text'], font=('Segoe UI', 9),
                width=10, anchor='w').pack(side=tk.LEFT)
        
        self.password_entry = tk.Entry(pwd_frame, show="●",
                                       font=('Segoe UI', 9),
                                       relief='solid', borderwidth=1)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.show_pwd_btn = tk.Button(pwd_frame, text="👁", width=3,
                                      command=self.toggle_password_visibility,
                                      bg=self.colors['button'], fg=self.colors['text'],
                                      relief='solid', borderwidth=1,
                                      font=('Segoe UI', 10),
                                      cursor='hand2')
        self.show_pwd_btn.pack(side=tk.LEFT)
        
        # Confirm password
        self.confirm_frame = tk.Frame(inner_frame, bg=self.colors['white'])
        self.confirm_frame.pack(fill=tk.X)
        
        tk.Label(self.confirm_frame, text="Confirm:", bg=self.colors['white'],
                fg=self.colors['text'], font=('Segoe UI', 9),
                width=10, anchor='w').pack(side=tk.LEFT)
        
        self.confirm_entry = tk.Entry(self.confirm_frame, show="●",
                                      font=('Segoe UI', 9),
                                      relief='solid', borderwidth=1)
        self.confirm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        # Spacer to align with password field
        tk.Frame(self.confirm_frame, width=34, bg=self.colors['white']).pack(side=tk.LEFT)
    
    def build_advanced_section(self, parent, row):
        """Build advanced options section."""
        # Advanced frame (always visible)
        self.advanced_frame = ttk.LabelFrame(parent, text="Advanced Options", padding="10")
        self.advanced_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        inner_frame = tk.Frame(self.advanced_frame, bg=self.colors['white'])
        inner_frame.pack(fill=tk.X)
        
        self.delete_cb = tk.Checkbutton(inner_frame,
                                        text="Securely delete original files after processing",
                                        variable=self.delete_original_var,
                                        bg=self.colors['white'], fg=self.colors['text'],
                                        font=('Segoe UI', 9),
                                        activebackground=self.colors['white'],
                                        selectcolor=self.colors['white'])
        self.delete_cb.pack(anchor='w')
    
    def build_status_section(self, parent, row):
        """Build status section."""
        frame = ttk.LabelFrame(parent, text="Status", padding="10")
        frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        inner_frame = tk.Frame(frame, bg=self.colors['white'])
        inner_frame.pack(fill=tk.X)
        
        # Status label
        self.status_label = tk.Label(inner_frame, text="READY",
                                    bg=self.colors['bg'], fg=self.colors['text'],
                                    font=('Segoe UI', 10, 'bold'),
                                    relief='solid', borderwidth=1,
                                    height=2)
        self.status_label.pack(fill=tk.X, pady=(0, 5))
        
        # Show log button
        self.log_btn = tk.Button(inner_frame, text="Show Log",
                                command=self.toggle_log,
                                bg=self.colors['button'], fg=self.colors['text'],
                                activebackground=self.colors['button_hover'],
                                relief='solid', borderwidth=1,
                                font=('Segoe UI', 9),
                                anchor='w',
                                cursor='hand2')
        self.log_btn.pack(fill=tk.X, pady=(0, 5))
        
        # Log text (hidden by default)
        self.log_frame = tk.Frame(inner_frame, bg=self.colors['white'])
        
        log_scroll = tk.Scrollbar(self.log_frame)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(self.log_frame, height=6,
                               bg=self.colors['white'], fg=self.colors['text'],
                               font=('Consolas', 8),
                               relief='solid', borderwidth=1,
                               state='disabled',
                               yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.config(command=self.log_text.yview)
    
    def build_action_buttons(self, parent, row):
        """Build action buttons."""
        btn_frame = tk.Frame(parent, bg=self.colors['bg'])
        btn_frame.grid(row=row, column=0, sticky=(tk.W, tk.E))
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        
        self.start_btn = tk.Button(btn_frame, text="START",
                                   command=self.process_files,
                                   bg=self.colors['accent'], fg='white',
                                   activebackground=self.colors['accent_hover'],
                                   activeforeground='white',
                                   relief='solid', borderwidth=1,
                                   font=('Segoe UI', 10, 'bold'),
                                   height=2,
                                   cursor='hand2')
        self.start_btn.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 3))
        
        close_btn = tk.Button(btn_frame, text="CLOSE",
                             command=self.root.quit,
                             bg=self.colors['button'], fg=self.colors['text'],
                             activebackground=self.colors['button_hover'],
                             activeforeground=self.colors['text'],
                             relief='solid', borderwidth=1,
                             font=('Segoe UI', 10, 'bold'),
                             height=2,
                             cursor='hand2')
        close_btn.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(3, 0))
    
    def set_operation(self, operation):
        """Set the operation mode."""
        self.operation_var.set(operation)
        
        if operation == "encrypt":
            self.encrypt_btn.config(bg=self.colors['accent'], fg='white')
            self.decrypt_btn.config(bg=self.colors['button'], fg=self.colors['text'])
            # Show confirm password
            self.confirm_frame.pack(fill=tk.X)
        else:
            self.decrypt_btn.config(bg=self.colors['accent'], fg='white')
            self.encrypt_btn.config(bg=self.colors['button'], fg=self.colors['text'])
            # Hide confirm password
            self.confirm_frame.pack_forget()
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            # Currently showing password, so hide it
            self.password_entry.config(show="●")
            self.confirm_entry.config(show="●")
            self.show_pwd_btn.config(bg=self.colors['button'])
            self.show_password_var.set(False)
        else:
            # Currently hiding password, so show it
            self.password_entry.config(show="")
            self.confirm_entry.config(show="")
            self.show_pwd_btn.config(bg=self.colors['accent'], fg='white')
            self.show_password_var.set(True)
    
    def toggle_log(self):
        """Toggle log visibility."""
        if self.show_log_var.get():
            self.log_frame.pack_forget()
            self.log_btn.config(text="Show Log")
            self.show_log_var.set(False)
            # Shrink window
            x = self.root.winfo_x()
            y = self.root.winfo_y()
            self.root.geometry(f"{self.window_width}x{self.window_height}+{x}+{y}")
        else:
            self.log_frame.pack(fill=tk.BOTH, expand=True)
            self.log_btn.config(text="Hide Log")
            self.show_log_var.set(True)
            # Expand window
            x = self.root.winfo_x()
            y = self.root.winfo_y()
            self.root.geometry(f"{self.window_width_expanded}x{self.window_height_expanded}+{x}+{y}")
    
    def add_files(self):
        """Add files to the list."""
        files = filedialog.askopenfilenames(title="Select Files to Process")
        
        if files:
            for file in files:
                if file not in self.selected_files:
                    self.selected_files.append(file)
                    self.file_listbox.insert(tk.END, Path(file).name)
            self.log(f"Added {len(files)} file(s)")
    
    def clear_files(self):
        """Clear the file list."""
        self.selected_files.clear()
        self.file_listbox.delete(0, tk.END)
        self.log("Cleared file list")
    
    def log(self, message):
        """Add message to log."""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def clear_form(self):
        """Clear form after processing."""
        self.password_entry.delete(0, tk.END)
        self.confirm_entry.delete(0, tk.END)
        self.selected_files.clear()
        self.file_listbox.delete(0, tk.END)
    
    def process_files(self):
        """Process selected files."""
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please add files to process.")
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password.")
            return
        
        operation = self.operation_var.get()
        
        # Check confirm password for encryption
        if operation == "encrypt":
            confirm = self.confirm_entry.get()
            if password != confirm:
                messagebox.showerror("Password Mismatch", "Passwords do not match.")
                return
        
        algorithm = self.algorithm_var.get()
        
        # Update status
        self.status_label.config(text="PROCESSING...")
        self.start_btn.config(state='disabled')
        
        # Process in thread
        thread = threading.Thread(target=self._process_worker,
                                 args=(operation, self.selected_files.copy(),
                                      password, algorithm))
        thread.daemon = True
        thread.start()
    
    def _process_worker(self, operation, files, password, algorithm):
        """Worker thread for processing files."""
        file_handler = FileHandler()
        
        try:
            if operation == "encrypt":
                if len(files) == 1:
                    self.log(f"Encrypting {Path(files[0]).name}...")
                    success, message, metadata = file_handler.encrypt_file(files[0], password, algorithm)
                    self.root.after(0, self._processing_complete, success, message)
                else:
                    self.log(f"Encrypting {len(files)} files...")
                    results = file_handler.batch_encrypt(files, password, algorithm)
                    success_count = sum(1 for r in results if r[1])  # r[1] is success boolean
                    failed_count = len(files) - success_count
                    if failed_count > 0:
                        message = f"Encrypted {success_count}/{len(files)} files ({failed_count} failed)"
                    else:
                        message = f"Successfully encrypted all {len(files)} files"
                    self.root.after(0, self._processing_complete,
                                   success_count > 0, message)
            else:  # decrypt
                if len(files) == 1:
                    self.log(f"Decrypting {Path(files[0]).name}...")
                    success, message, metadata = file_handler.decrypt_file(files[0], password)
                    self.root.after(0, self._processing_complete, success, message)
                else:
                    self.log(f"Decrypting {len(files)} files...")
                    results = file_handler.batch_decrypt(files, password)
                    success_count = sum(1 for r in results if r[1])  # r[1] is success boolean
                    failed_count = len(files) - success_count
                    if failed_count > 0:
                        message = f"Decrypted {success_count}/{len(files)} files ({failed_count} failed)"
                    else:
                        message = f"Successfully decrypted all {len(files)} files"
                    self.root.after(0, self._processing_complete,
                                   success_count > 0, message)
        except Exception as e:
            self.root.after(0, self._processing_complete, False, f"Error: {str(e)}")
    
    def _processing_complete(self, success, message):
        """Handle processing completion."""
        self.log(message)
        
        if success and self.delete_original_var.get():
            self.log("Securely deleting original files...")
            file_handler = FileHandler()
            for file in self.selected_files:
                try:
                    file_handler.secure_delete(file)
                except Exception as e:
                    self.log(f"Could not delete {Path(file).name}: {str(e)}")
        
        # Re-enable UI
        self.start_btn.config(state='normal')
        
        # Update status
        if success:
            self.status_label.config(text="DONE")
            self.clear_form()
            messagebox.showinfo("Success", message)
        else:
            self.status_label.config(text="ERROR")
            messagebox.showerror("Error", message)


def main():
    """Main entry point."""
    root = tk.Tk()
    app = RufusStyleGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
