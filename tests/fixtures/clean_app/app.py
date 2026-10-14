import json


def handler(event):
    return json.dumps({"ok": True})
