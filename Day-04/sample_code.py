def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query