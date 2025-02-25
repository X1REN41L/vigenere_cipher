#################
#### IMPORTS ####
#################

import tkinter as tk
from tkinter import ttk
from datetime import datetime
import re

#####################
#### MAIN LOGIC ####
#####################

def process(message, password, mode):
    if re.search(r'\d', message) or re.search(r'\d', password):
        log("Cannot cipher numbers. Please spell them out.")
        return ""
    
    message1 = message.replace(" ", "").upper()
    password1 = password.replace(" ", "").upper()
    processed_password = (password1 * (len(message1) // len(password1))) + password1[:(len(message1) % len(password1))]
    output_text = ""
    
    if mode == "0":
        for m, p in zip(message1, processed_password):
            value5 = ((ord(m) - ord('A')) + (ord(p) - ord('A'))) % 26
            output_text += chr(value5 + ord('A'))
    else:
        for d, p in zip(message1, processed_password):
            value4 = ((ord(d) - ord('A')) - (ord(p) - ord('A')) + 26) % 26
            output_text += chr(value4 + ord('A'))
    
    return output_text

#####################
#### PROCESSING ####
#####################

def process_input():
    try:
        input_text = input_textbox.get("1.0", tk.END).strip()
        mode = option_var.get()
        password = password_entry.get()
        
        if not input_text:
            log("Input cannot be empty!")
            return
        
        if not password:
            log("Password cannot be empty!")
            return

        output_text = process(input_text, password, mode)
        
        if output_text:
            output_textbox.config(state="normal")
            output_textbox.delete("1.0", tk.END)
            output_textbox.insert("1.0", output_text)
            output_textbox.config(state="disabled")
            log(f"Processing {'Encoding' if mode == '0' else 'Decoding'} completed successfully.")
    except Exception as e:
        log(f"Error: {e}")

##################
#### LOGGING ####
##################

def log(message):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_textbox.config(state="normal")
    log_textbox.insert(tk.END, f"[{current_time}] {message}\n")
    log_textbox.see(tk.END)
    log_textbox.config(state="disabled")

####################
#### UTILITIES ####
####################

def copy_output():
    root.clipboard_clear()
    root.clipboard_append(output_textbox.get("1.0", tk.END).strip())

def paste_input():
    input_textbox.insert(tk.END, root.clipboard_get())

def clear_input():
    input_textbox.delete("1.0", tk.END)

#####################
#### MAIN WINDOW ####
#####################

root = tk.Tk()
root.title("Vigenère Cipher Encoder Decoder")
root.geometry("800x600")
root.minsize(800, 600)

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)
main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=0)
main_frame.columnconfigure(2, weight=1)
main_frame.rowconfigure(2, weight=1)
main_frame.rowconfigure(4, weight=1)

#######################
#### CREDIT LABEL ####
#######################
credit_label = ttk.Label(main_frame, text="BY S M JAYEED AJWAD | smjayeedajwad@gmail.com", font=("Monaco", 10, "bold"))
credit_label.grid(row=0, column=0, columnspan=3, pady=5, sticky="w")

###################
#### INPUT BOX ####
###################
input_label = ttk.Label(main_frame, text="Input:")
input_label.grid(row=1, column=0, sticky="nw")
input_textbox = tk.Text(main_frame, height=10, wrap=tk.WORD)
input_textbox.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")

####################
#### OUTPUT BOX ####
####################
output_label = ttk.Label(main_frame, text="Output:")
output_label.grid(row=1, column=2, sticky="nw")
output_textbox = tk.Text(main_frame, height=10, wrap=tk.WORD, state="disabled")
output_textbox.grid(row=2, column=2, padx=10, pady=5, sticky="nsew")

#################
#### OPTIONS ####
#################
options_frame = ttk.LabelFrame(main_frame, text="Options", padding=10)
options_frame.grid(row=2, column=1, padx=10, pady=5, sticky="ns")
options_frame.columnconfigure(0, weight=1)

option_var = tk.StringVar(value="0")
option_label = ttk.Label(options_frame, text="Mode:")
option_label.pack()
option1_radio = ttk.Radiobutton(options_frame, text="Encoder", variable=option_var, value="0")
option1_radio.pack(anchor="w")
option2_radio = ttk.Radiobutton(options_frame, text="Decoder", variable=option_var, value="1")
option2_radio.pack(anchor="w")

password_label = ttk.Label(options_frame, text="Password:")
password_label.pack()
password_entry = ttk.Entry(options_frame, show="*")
password_entry.pack()

process_button = ttk.Button(options_frame, text="Process", command=process_input)
process_button.pack(pady=5)
copy_button = ttk.Button(options_frame, text="Copy Output", command=copy_output)
copy_button.pack(pady=2)
paste_button = ttk.Button(options_frame, text="Paste Input", command=paste_input)
paste_button.pack(pady=2)
clear_button = ttk.Button(options_frame, text="Clear Input", command=clear_input)
clear_button.pack(pady=2)

####################
#### LOG WINDOW ####
####################
log_label = ttk.Label(main_frame, text="Log:")
log_label.grid(row=3, column=0, columnspan=3, sticky="w")
log_textbox = tk.Text(main_frame, height=5, wrap=tk.WORD, state="disabled")
log_textbox.grid(row=4, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")

###################
#### MAIN LOOP ####
###################
root.mainloop()
