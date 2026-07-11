import re

filepath = r"C:\Users\user\Documents\kinnector\kinnector-agent\src\heuristics.rs"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Remove the unix MetadataExt imports
content = re.sub(r"use std::os::unix::fs::MetadataExt;\s*", "", content)

# Add is_naked_tty if it's missing (it should be right before `let threshold = if is_untrusted {`)
if "let is_naked_tty =" not in content:
    content = content.replace("let threshold = if is_untrusted {", "let is_naked_tty = false;\n        let threshold = if is_untrusted {")

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed remaining Unix logic.")
