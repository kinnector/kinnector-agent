import re

filepath = r"C:\Users\user\Documents\kinnector\kinnector-agent\src\heuristics.rs"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Remove the hVNC block entirely
content = re.sub(r"// 1\. hVNC Display Mismatch Detection.*?// 2\. Interpreter Inline", r"// 2. Interpreter Inline", content, flags=re.DOTALL)

# Fix is_stdin_tty
content = re.sub(r"let is_stdin_tty = if let Ok\(target\).*?else \{\s*false\s*\};", "let is_stdin_tty = false;", content, flags=re.DOTALL)

# Fix get_parent_exe_path for sigma
content = re.sub(r"if let Ok\(parent_path\) = std::fs::read_link\(format!\(\"/proc/\{\}/exe\", p_pid\)\) \{.*?\}", "", content, flags=re.DOTALL)

# Fix uid check
content = re.sub(r"#[cfg(unix)]\s*use std::os::unix::fs::MetadataExt;\s*", "", content)
content = re.sub(r"m.uid\(\)", "0", content)

# Fix inode check
content = re.sub(r"let inode = metadata\.ino\(\);", "let inode = 0;", content)

# Fix get_process_env_all
content = re.sub(r"proc_info\.env = get_process_env_all\(pid\);", "proc_info.env = std::collections::HashMap::new();", content)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("Cleaned up unix specifics from heuristics.rs")
