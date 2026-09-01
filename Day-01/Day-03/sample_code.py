from flask import request


def login():
    username = request.args.get("username")

    query = "SELECT * FROM users WHERE name='" + username + "'"

    return query