import tkinter as tk
from tkinter import filedialog, messagebox

# Caesar Cipher Logic
def caesar_cipher(text, shift, encrypt=True):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            direction = shift if encrypt else -shift
            result += chr((ord(char) - base + direction) % 26 + base)
        else:
            result += char
    return result

# Encrypt Handler
def encrypt_text():
    try:
        shift = int(shift_entry.get())
        message = message_entry.get("1.0", tk.END).strip()
        encrypted = caesar_cipher(message, shift, encrypt=True)
        output_entry.config(state='normal')
        output_entry.delete("1.0", tk.END)
        output_entry.insert(tk.END, encrypted)
        output_entry.config(state='disabled')
    except ValueError:
        messagebox.showerror("Error", "Shift value must be a number.")

# Decrypt Handler
def decrypt_text():
    try:
        shift = int(shift_entry.get())
        message = message_entry.get("1.0", tk.END).strip()
        decrypted = caesar_cipher(message, shift, encrypt=False)
        output_entry.config(state='normal')
        output_entry.delete("1.0", tk.END)
        output_entry.insert(tk.END, decrypted)
        output_entry.config(state='disabled')
    except ValueError:
        messagebox.showerror("Error", "Shift value must be a number.")

# Copy to Clipboard
def copy_output():
    root.clipboard_clear()
    output_text = output_entry.get("1.0", tk.END).strip()
    root.clipboard_append(output_text)
    messagebox.showinfo("Copied", "Output copied to clipboard.")


def save_output():
    output_text = output_entry.get("1.0", tk.END).strip()
    if output_text:
        file = filedialog.asksaveasfile(defaultextension=".txt",
                                        filetypes=[("Text files", "*.txt")])
        if file:
            file.write(output_text)
            file.close()
            messagebox.showinfo("Saved", "Output saved to file.")
    else:
        messagebox.showwarning("Warning", "No output to save.")


root = tk.Tk()
root.title("Caesar Cipher Tool")
root.geometry("600x500")
root.configure(bg="#282c34")


title = tk.Label(root, text="Caesar Cipher Encryption & Decryption", bg="#282c34", fg="white", font=("Helvetica", 16, "bold"))
title.pack(pady=10)


tk.Label(root, text="Enter Your Message:", bg="#282c34", fg="white", font=("Helvetica", 12)).pack()
message_entry = tk.Text(root, height=5, width=60)
message_entry.pack(pady=5)


tk.Label(root, text="Enter Shift Value:", bg="#282c34", fg="white", font=("Helvetica", 12)).pack()
shift_entry = tk.Entry(root)
shift_entry.pack(pady=5)


btn_frame = tk.Frame(root, bg="#282c34")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Encrypt", command=encrypt_text, width=10).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Decrypt", command=decrypt_text, width=10).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Copy", command=copy_output, width=10).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Save", command=save_output, width=10).grid(row=0, column=3, padx=5)


tk.Label(root, text="Output:", bg="#282c34", fg="white", font=("Helvetica", 12)).pack()
output_entry = tk.Text(root, height=5, width=60, state='disabled', bg="#f0f0f0")
output_entry.pack(pady=5)

root.mainloop()
