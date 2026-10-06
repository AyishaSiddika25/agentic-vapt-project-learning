import os


def get_database_config():
    username = os.getenv("DEMO_DATABASE_USERNAME", "admin")
    password = os.getenv("DEMO_DATABASE_PASSWORD", "")

    return username, password
