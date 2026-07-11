import json

input_path = r"C:\Users\user\.gemini\antigravity-cli\brain\28b2a4e4-343d-48f8-9efc-2afafae9c00d\.system_generated\logs\transcript_full.jsonl"
output_path = r"C:\Users\user\Documents\kinnector\kinnector-agent\src\heuristics.rs"

latest_content = None

with open(input_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            data = json.loads(line)
            if data.get("type") == "PLANNER_RESPONSE":
                for call in data.get("tool_calls", []):
                    if call.get("name") == "replace_file_content" or call.get("name") == "write_to_file":
                        args = call.get("args", {})
                        target = args.get("TargetFile") or args.get("AbsolutePath")
                        if target and "heuristics.rs" in target:
                            pass # Wait, if it was replace_file_content, it doesn't have the full file
        except Exception:
            pass

