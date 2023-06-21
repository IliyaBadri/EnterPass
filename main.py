import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import os
import csv
import argon2
import base64



def encrypt_text_aes_cbc(text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encoded_text = text.encode('utf-8') 
    padded_text = pad(encoded_text, AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)

    base64_text = base64.b64encode(encrypted_text)
    decoded_base64_text = base64_text.decode('utf-8')

    return decoded_base64_text

def decrypt_text_aes_cbc(decoded_base64_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    encoded_base64_text = decoded_base64_text.encode('utf-8')
    encrypted_text = base64.b64decode(encoded_base64_text)

    padded_text = cipher.decrypt(encrypted_text)
    encoded_text = unpad(padded_text, AES.block_size)
    decoded_text = encoded_text.decode('utf-8')
    return decoded_text

def create_aes_key(password):
    while len(password) < 32:
        password += password
    key = password[:32].encode('utf-8')
    return key

def is_valid_aes_key(key):
    try:
        AES.new(key, AES.MODE_CBC, b'\x00' * 16) 
        return True
    except (ValueError, TypeError):
        return False

def can_create_aes_key(password):
    key = create_aes_key(password)
    return is_valid_aes_key(key)

def configure_window_grids(window, rows, columns):
    for i in range(rows):
        window.rowconfigure(i, weight=1)
    for i in range(columns):
        window.columnconfigure(i, weight=1)

def get_password(text):
    password = None
    
    def return_password():
        nonlocal password
        password = master_password_entry.get()
        window.destroy() 
    def cancel():
        window.destroy()
        sys.exit()
    def disable_close():
        pass
    def show_error():
        messagebox.showerror("Error", "Your password is invalid:\nYou have probabely leaved the password input empty.")

    window = tk.Tk()
    window.resizable(False, False)
    window.protocol("WM_DELETE_WINDOW", disable_close)
    window.title('Auth')
    
    window.iconphoto(False, tk.PhotoImage(file="enterpass.png"))
    configure_window_grids(window, 3, 2)
    tk.Label(window, text=text).grid(
        row=0,
        columnspan=2,
        padx=5, 
        pady=5
    )
    master_password_entry = tk.Entry(window, show="*")
    master_password_entry.grid(
        row=1, 
        columnspan=2, 
        padx=5, 
        pady=5, 
        sticky='ew'
    )
    tk.Button(window, text="Continue", command=return_password).grid(
        row=2, 
        column=0, 
        padx=5, 
        pady=5
    )
    tk.Button(window, text="Cancel", command=cancel).grid(
        row=2, 
        column=1, 
        padx=5, 
        pady=5
    )
    
    window.mainloop()

    while (
        password == None or
        not isinstance(password, str) or
        password == '' or
        not can_create_aes_key(password)
    ):
        show_error()
        password = get_password(text)
    
    return password

def make_key_hash(key):
    hasher = argon2.PasswordHasher()
    key_hash = hasher.hash(key)
    return key_hash

def read_database():
    database_rows = []
    database_file = open('database.csv', 'r')
    database_reader = csv.DictReader(database_file)
    for database_row in database_reader:
        database_columns = []
        for database_column in database_row:
            database_columns.append(database_row[database_column])
        database_rows.append(database_columns)
    database_file.close()
    return database_rows
    

def append_database(data):
    rows = read_database()
    database_file = open('database.csv', 'a', newline='')
    database_writer = csv.writer(database_file)
    if not len(rows) == 0:
        last_id = rows[-1][0]
        data.insert(0, int(last_id) + 1)
        database_writer.writerow(data)
    else:
        data.insert(0, 1)
        database_writer.writerow(data)
    database_file.close()


def edit_database(Id, data):
    rows = read_database()
    

    for row in rows:
        if row[0] == Id:
            row[1:] = data

    header = ['id', 'url', 'username', 'password', 'comment']
    rows.insert(0, header)

    database_file = open('database.csv', 'w', newline='')
    database_writer = csv.writer(database_file)
    database_writer.writerows(rows)
    database_file.close()

def delete_database(Id):
    rows = read_database()
    

    for row in rows:
        if int(row[0]) == int(Id):
            rows.remove(row)

    header = ['id', 'url', 'username', 'password', 'comment']
    rows.insert(0, header)

    database_file = open('database.csv', 'w', newline='')
    database_writer = csv.writer(database_file)
    database_writer.writerows(rows)
    database_file.close()

def build_password_manager(password): 
    key = create_aes_key(password)
    key_hash = make_key_hash(key)    
    encoded_key_hash = key_hash.encode('utf-8')
    key_hash_file = open('key.hash', 'wb')
    key_hash_file.write(encoded_key_hash)
    key_hash_file.close()

    iv = get_random_bytes(16)
    iv_file = open('key.iv', 'wb')
    iv_file.write(iv)
    iv_file.close()

    header = ['id', 'url', 'username', 'password', 'comment']
    database_file = open('database.csv', 'w', newline='')
    writer = csv.writer(database_file)
    writer.writerow(header)
    database_file.close()

def is_correct_password(password):
    key = create_aes_key(password)
    hasher = argon2.PasswordHasher()
    key_hash_file = open('key.hash', 'rb')
    key_hash = key_hash_file.read()
    try:
        correct = hasher.verify(key_hash, key)
        return correct
    except argon2.exceptions.VerificationError:
        return False
    except argon2.exceptions.VerifyMismatchError:
        return False


def make_control_panel_outputs(root_frame):
    headers = ['id', 'url','username', 'password', 'comment']
    outputs = []
    for i in range(len(headers)):
        outputs.append(tk.Entry(root_frame))
    for i in range(len(outputs)):
        tk.Label(root_frame, text=f'{headers[i]}:').grid(row=(i+1)*2-1)
        outputs[i].grid(row=(i+1)*2, sticky='ew')
        outputs[i].config(state='readonly')
    return outputs

def make_control_panel_inputs(root_frame):
    headers = ['id', 'url','username', 'password', 'comment']
    inputs = []
    for i in range(len(headers)):
        inputs.append(tk.Entry(root_frame))
    for i in range(len(inputs)):
        tk.Label(root_frame, text=f'{headers[i]}:').grid(row=(i+1)*2-1)
        inputs[i].grid(row=(i+1)*2, sticky='ew')
    return inputs

def make_ungrided_tree(root_frame):

    headers = ['id', 'url','username', 'password', 'comment']
    tree = ttk.Treeview(root_frame, columns=(headers[0], headers[1], headers[2], headers[3], headers[4]), show='headings')

    tree.heading(headers[0], text=headers[0])
    tree.heading(headers[1], text=headers[1])
    tree.heading(headers[2], text=headers[2])
    tree.heading(headers[3], text=headers[3])
    tree.heading(headers[4], text=headers[4])

    scrollbar = ttk.Scrollbar(root_frame, orient='vertical', command=tree.yview)

    tree.configure(yscrollcommand=scrollbar.set)

    return (tree, scrollbar)

def decrypt_string(string, password):
    iv_file = open('key.iv', 'rb')
    iv = iv_file.read()
    iv_file.close()
    key = create_aes_key(password)
    return decrypt_text_aes_cbc(string, key, iv)

def encrypt_string(string, password):
    iv_file = open('key.iv', 'rb')
    iv = iv_file.read()
    iv_file.close()
    key = create_aes_key(password)

    if string == None or string == '':
        string = f'N/A(#{base64.b64encode(get_random_bytes(4)).decode("utf-8")})'
    return encrypt_text_aes_cbc(string, key, iv)


def make_password_manager_tree(root_frame, password, outputs):
    (tree, scrollbar) = make_ungrided_tree(root_frame)
    rows = read_database()
    for row in rows:
        the_item_url = decrypt_string(row[1],password)
        the_item_username = decrypt_string(row[2], password)
        the_item_password = decrypt_string(row[3], password)
        the_item_comment = decrypt_string(row[4], password)
        tree.insert('', 'end', values=(row[0], the_item_url, the_item_username, the_item_password, the_item_comment))

    tree.grid(row=0, column=0, sticky='nsew', rowspan=10)
    scrollbar.grid(row=0, column=1, sticky='nsw', rowspan=10)

    configure_window_grids(root_frame, 1, 1)

    def on_select(event):
        selected_item = tree.focus()
        selected_values = tree.item(selected_item)['values']
        for i in range(len(outputs)):
            outputs[i].config(state='normal')
            outputs[i].delete(0, tk.END)
            outputs[i].insert(0, selected_values[i])
            outputs[i].config(state='readonly')
        root_frame.update()
    
    # Bind the selection event to the on_select function
    tree.bind('<<TreeviewSelect>>', on_select)

    return tree

def reload_password_manager_tree(tree, root_frame, password, outputs):
    tree.destroy()
    make_password_manager_tree(root_frame, password, outputs)

def add_password(password, inputs, tree, root_frame, outputs):

    encrypted_url = encrypt_string(inputs[1].get(), password)
    encrypted_username = encrypt_string(inputs[2].get(), password)
    encrypted_password = encrypt_string(inputs[3].get(), password)
    encrypted_comment = encrypt_string(inputs[4].get(), password)

    append_database([encrypted_url,encrypted_username, encrypted_password, encrypted_comment])
    reload_password_manager_tree(tree, root_frame, password, outputs)

def edit_password(password, inputs, tree, root_frame, outputs):
    if inputs[0].get().isdigit():
        Id = int(inputs[0].get())
        encrypted_url = encrypt_string(inputs[1].get(), password)
        encrypted_username = encrypt_string(inputs[2].get(), password)
        encrypted_password = encrypt_string(inputs[3].get(), password)
        encrypted_comment = encrypt_string(inputs[4].get(), password)

        edit_database(Id, [encrypted_url,encrypted_username, encrypted_password, encrypted_comment])
        reload_password_manager_tree(tree, root_frame, password, outputs)

def delete_password(password, inputs, tree, root_frame, outputs):
    if inputs[0].get().isdigit():
        Id = int(inputs[0].get())
        delete_database(Id)
        reload_password_manager_tree(tree, root_frame, password, outputs)

    
def open_password_manager(password):
    window = tk.Tk()
    window.title('EnterPass open-source password manager')
    window.iconphoto(False, tk.PhotoImage(file="enterpass.png"))


    controls_frame = ttk.Labelframe(window, text='Controls')
    controls_frame.grid(row=0, column=2, sticky='n')

    output_frame = ttk.Labelframe(controls_frame, text='Output')
    output_frame.grid(row=0, sticky='n')

    input_frame = ttk.Labelframe(controls_frame, text='Input')
    input_frame.grid(row=1, sticky='n')

    outputs = make_control_panel_outputs(output_frame)
    inputs = make_control_panel_inputs(input_frame)
    tree = make_password_manager_tree(window, password, outputs)


    ttk.Button(controls_frame, text='Add a new password', command=lambda: add_password(
        password, 
        inputs, 
        tree, 
        window, 
        outputs
    )).grid(row=2, sticky='nsew')

    ttk.Button(controls_frame, text='Edit password by ID', command=lambda: edit_password(
        password, 
        inputs, 
        tree, 
        window, 
        outputs
    )).grid(row=3, sticky='nsew')

    ttk.Button(controls_frame, text='Delete password by ID', command=lambda: delete_password(
        password, 
        inputs, 
        tree, 
        window, 
        outputs
    )).grid(row=4, sticky='nsew')

    ttk.Button(controls_frame, text='Reload the database', command=lambda: reload_password_manager_tree(
        tree, 
        window, 
        password, 
        outputs
    )).grid(row=5, sticky='nsew')
    

    

    window.mainloop()



def run():
    password = get_password("Please enter your master password:")
    password_is_correct = False
    while not password_is_correct:
        password_is_correct = is_correct_password(password)
        if not password_is_correct:
            messagebox.showerror("Error", "Your password is not correct.")
            password = get_password("Please enter your master password:")
    open_password_manager(password)
    
def setup():
    new_password = get_password("Please enter a new master password:")
    build_password_manager(new_password)
    run()

def main():
    if not (
        os.path.exists('key.hash') and
        os.path.exists('key.iv') and 
        os.path.exists('database.csv')
    ):
        setup()
    else:
        run()

if __name__ == '__main__':
    main()
