import ast

code = """
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
"""

tree = ast.parse(code)

print("AST Structure:")
print(ast.dump(tree, indent=2))