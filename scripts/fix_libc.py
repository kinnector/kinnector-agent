import re

filepath = r"C:\Users\user\Documents\kinnector\kinnector-agent\src\heuristics.rs"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Replace all occurrences of libc::kill(...) with crate::os_utils calls
content = re.sub(r"libc::kill\(([^ ]+) as libc::pid_t, libc::SIGKILL\);", r"crate::os_utils::terminate_process(\1);", content)
content = re.sub(r"libc::kill\(([^ ]+) as libc::pid_t, libc::SIGSTOP\);", r"crate::os_utils::suspend_process(\1);", content)
content = re.sub(r"libc::kill\(([^ ]+) as libc::pid_t, libc::SIGCONT\);", r"crate::os_utils::release_process(\1);", content)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed libc::kill calls in heuristics.rs")
