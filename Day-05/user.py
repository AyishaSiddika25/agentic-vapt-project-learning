def get_user(username):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    return query