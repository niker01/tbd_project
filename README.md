## 📌 Overview

**TBD Project** is a Python-based desktop application designed for **access control management and user administration**.

The system allows administrators to:

* Create and manage users
* Assign roles and permissions
* Control access to specific files and resources

Each user can log into the system and will only have access to the files and functionality explicitly permitted by the administrator.

This project demonstrates the implementation of:

* Role-based access control (RBAC)
* User authentication and authorization
* File-level access restrictions
* Administrative management tools within a GUI application

The application is intended as a learning project showcasing how secure access systems and permission management can be structured in a standalone desktop environment.

📁 Project Structure
TBD_Project/
│
├── auth/              # Authentication logic (login, validation)
├── database/          # Database connection and queries
├── gui/               # GUI components and main application
│   └── gui_main.py    # Entry point of the application
│
├── Data/              # Local data storage (e.g., SQLite DB)
│
├── build/             # Temporary build files (ignored in Git)
├── dist/              # Compiled executable output
│
├── .gitignore         # Git ignore rules
└── README.md          # Project documentation
⚙️ Requirements
Python 3.9+
pip (Python package manager)
🚀 Getting Started
1. Clone the Repository
git clone https://github.com/your-username/tbd-project.git
cd tbd-project
2. Create a Virtual Environment
python -m venv venv

Activate it:

Windows

venv\Scripts\activate


3. Install Dependencies

If a requirements file exists:

pip install -r requirements.txt

If not, install manually (example):

pip install tkinter
4. Run the Application
python gui/main.py

This project includes basic security mechanisms such as:

Input validation
Login attempt handling
Structured authentication logic