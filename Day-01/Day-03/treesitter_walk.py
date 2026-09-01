from tree_sitter import Language, Parser
import tree_sitter_python as tspython


PY_LANGUAGE = Language(tspython.language())

parser = Parser(PY_LANGUAGE)


with open("sample_code.py", "r", encoding="utf-8") as file:
    source_code = file.read()


tree = parser.parse(source_code.encode("utf-8"))


def print_tree(node, level=0):
    print("  " * level + f"{node.type} [{node.start_point} - {node.end_point}]")

    for child in node.children:
        print_tree(child, level + 1)


print("Tree-sitter Syntax Tree Nodes:")
print_tree(tree.root_node)