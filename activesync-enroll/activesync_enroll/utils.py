import re
from xml.sax.saxutils import escape as _xml_escape


def xml_escape(text: str) -> str:
    return _xml_escape(text, {'"': "&quot;", "'": "&apos;"})


def get_from_xml(tag: str, xml_string: str) -> str | None:
    pattern = rf'<(?:[\w]+:)?{tag}\s*>(.*?)</(?:[\w]+:)?{tag}>'
    match = re.search(pattern, xml_string, re.DOTALL)
    return match.group(1) if match else None
