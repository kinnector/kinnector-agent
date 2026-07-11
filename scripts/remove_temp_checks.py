import re

filepath = r"C:\Users\user\Documents\kinnector\kinnector-context\detection-engine\windows.md"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Replace mentions of %TEMP%, Downloads, Temp
content = re.sub(r"user-writeable directory \(such as `Downloads` or `Temp`\)", r"untrusted execution origin (validated via MOTW ZoneIdentifier)", content, flags=re.IGNORECASE)
content = re.sub(r"user-writable path \(`%TEMP%`, `Downloads`, `C:\\Users\\Public`\)", r"untrusted execution origin (validated via MOTW ZoneIdentifier)", content, flags=re.IGNORECASE)
content = re.sub(r"\(Temp, Downloads, AppData\\Local\\...\)", r"(untrusted execution origin)", content, flags=re.IGNORECASE)
content = re.sub(r"`%TEMP%`, `Downloads`, or a UNC path", r"an untrusted execution origin or a UNC path", content, flags=re.IGNORECASE)
content = re.sub(r"to `%TEMP%` within 5 seconds", r"within 5 seconds", content, flags=re.IGNORECASE)
content = re.sub(r"\(%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `Downloads`\)", r"(untrusted execution origin)", content, flags=re.IGNORECASE)
content = re.sub(r"from `%TEMP%` or `%APPDATA%`", r"from an untrusted execution origin", content, flags=re.IGNORECASE)
content = re.sub(r"drops a file to `%TEMP%`", r"drops a file", content, flags=re.IGNORECASE)
content = re.sub(r"drops file to %TEMP% / Downloads", r"drops file", content, flags=re.IGNORECASE)
content = re.sub(r"`%TEMP%`, `Downloads`, `Desktop`, `C:\\Users\\Public`, or `%ProgramData%`", r"an untrusted execution origin", content, flags=re.IGNORECASE)
content = re.sub(r"\(%TEMP%, Downloads, Desktop, C:\\Users\\Public, %ProgramData%\)", r"(untrusted execution origin)", content, flags=re.IGNORECASE)
content = re.sub(r"\(Process executes from Temp/Roaming\)", r"(Process executes from untrusted origin)", content, flags=re.IGNORECASE)
content = re.sub(r"`%TEMP%\\safe.db`", r"`C:\\safe.db`", content, flags=re.IGNORECASE)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("Done replacing.")
