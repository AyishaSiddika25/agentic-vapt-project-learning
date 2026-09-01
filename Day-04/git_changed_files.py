import subprocess


result = subprocess.run(
    ["git", "diff", "--name-only"],
    capture_output=True,
    text=True
)


print("Changed files:")
print(result.stdout)