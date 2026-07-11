import re

filepath = r"C:\Users\user\Documents\kinnector\kinnector-agent\src\heuristics.rs"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Fix packed struct unaligned references
content = re.sub(r"println!\(\"\[Heuristic G\] Unsigned Dropper beaconing detected from PID \{\}\", header\.pid\);", r"let pid = header.pid; println!(\"[Heuristic G] Unsigned Dropper beaconing detected from PID {}\", pid);", content)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed unaligned references in heuristics.rs")
