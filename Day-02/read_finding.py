import json
import os

file_path = os.path.join(os.path.dirname(__file__), "finding.json")

with open(file_path, "r") as file:
    finding = json.load(file)

print("Security Finding")
print("-----------------")
print("Type:", finding["finding_type"])
print("Severity:", finding["severity"])
print("File:", finding["file"])
print("Line:", finding["line"])
print("Status:", finding["status"])