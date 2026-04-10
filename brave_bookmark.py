import os, json

def get_bookmarks(profile_path):
    path = os.path.join(profile_path, "Bookmarks")
    if not os.path.exists(path): return []
    results = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Bookmarks have a nested structure; we'll grab the 'roots'
            def parse_nodes(node):
                if node.get("type") == "url":
                    results.append((node.get("name"), node.get("url")))
                if "children" in node:
                    for child in node["children"]: parse_nodes(child)
            
            for key in data.get("roots", {}):
                parse_nodes(data["roots"][key])
    except: pass
    return results