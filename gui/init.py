from database.db import init_db
from gui.gui_main import run_app

if __name__ == "__main__":
    init_db()
    run_app()