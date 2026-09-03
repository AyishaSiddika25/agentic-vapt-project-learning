def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return query


def greet_user(name):
    message = "Hello " + name
    return message