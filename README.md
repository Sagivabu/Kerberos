# Setup:
## Install 'poetry' - "pip install poetry'
### NOTE: poetry is a library used to create packages in python so it will be easy to build and install the package and its dependecies.
## Install the project:
### Open CMD\Terminal in the project path ".../Kerberos"
### Run command - "poetry install"
## Run the project - "main.py"

# Structure:
## kerberos is the package name
## All files are organized in folders
## The folders:
### 'authserver' - includes the files to run the auth_server
### 'clientapp' - includes the files to run a client app, it has cmd GUI to get commands as input. Multiple clients are enabled
### 'msgserver' - includes the files to run a message server, it has cmd GUI to get inputs for register the server. Multiple clients are enabled
### 'main.py' - Auto-run: 1 auth, 1 msg server, 1 client. Please run manually for multiple clients and servers
### 'attacker.py' - Question number 2 in the assignment - Run it separately
