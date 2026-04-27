import base64
import json
import re
from xml.sax.saxutils import escape as _xml_escape


def xml_escape(text: str) -> str:
    return _xml_escape(text, {'"': "&quot;", "'": "&apos;"})

def get_from_xml(tag: str, xml_string: str) -> str | None:
    pattern = rf'<(?:[\w]+:)?{tag}\s*>(.*?)</(?:[\w]+:)?{tag}>'
    match = re.search(pattern, xml_string, re.DOTALL)
    return match.group(1) if match else None

def json_b64_header(data: dict) -> str:
    return base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
