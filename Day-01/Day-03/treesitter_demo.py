from tree_sitter import Language, Parser
import tree_sitter_python as tspython


PY_LANGUAGE = Language(tspython.language())

parser = Parser(PY_LANGUAGE)


with open("Day-03/sample_code.py", "r", encoding="utf-8") as file:
    source_code = file.read()


tree = parser.parse(source_code.encode("utf-8"))


print("Tree-sitter Syntax Tree:")
print(tree.root_node)