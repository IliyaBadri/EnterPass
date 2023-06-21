# EnterPass Documentation


EnterPass is an open-source password manager developed by EnterACE repository. It is designed to securely store and manage passwords using AES encryption and Argon2 key hashing.

  

## Features

 - AES encryption in CBC mode for secure storage of passwords
 - Argon2 key hashing for enhanced password security
 - User-friendly graphical user interface using tkinter library
 - Ability to add, edit, and delete passwords in the password manager
 - Encrypted storage of passwords in a CSV database file

## Requirements

 - Python 3.x

 - tkinter library

 - pycryptodome library

 - argon2-cffi library

## Installation

**Clone the EnterPass repository from GitHub:**

    git clone https://github.com/IliyaBadri/EnterPass.git

**move into the source code directory:**
	
	cd enterpass/

**Install the required dependencies:**


    pip install -r requirements.txt

## Usage

To run the EnterPass password manager, execute the following command in the terminal:

*on linux:*

    python3 enterpass.py


 *on windows:*


    python enterpass.py

 - The password manager will prompt you to enter your master password.
   If it's your first time running EnterPass, you'll be asked to create
   a new master password.

  

 - Once you've entered the correct master password, the password manager
   interface will open, allowing you to add, edit, and delete passwords.
   The passwords are securely encrypted and stored in the database.csv
   file.

  

**Note: It's important to remember your master password, as it cannot be recovered if lost.**

  

## Contributing

If you would like to contribute to the development of EnterPass, you can fork the repository, make your changes, and submit a pull request. Contributions such as bug fixes, new features, and documentation improvements are welcome.

  


## License


EnterPass is released under the [MIT License](https://github.com/IliyaBadri/EnterPass/blob/main/LICENSE).

  

## Disclaimer

EnterPass is provided as-is without any warranty. The developers and contributors of EnterPass are not responsible for any damages or losses arising from its use.
