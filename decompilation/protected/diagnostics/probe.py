"""Bounded lexical inspection of inert Luau source; no interpreter or VM."""
from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_SOURCE = 8 * 1024 * 1024
MAX_TOKENS = 300_000
LEX = re.compile(r"(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
                 r"|[A-Za-z_][A-Za-z_0-9]*|\.\.\.|\.\.=|//=|==|~=|<=|>=|\+=|-=|\*=|/=|%=|\^=|//|\.\.|::|->|.",
                 re.DOTALL)

@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int
    string: bool = False

def tokens(source: str) -> list[Token]:
    if len(source.encode()) > MAX_SOURCE:
        raise ValueError("source budget")
    result, at = [], 0
    while at < len(source):
        if source[at] in " \t\r\n\v\f":
            at += 1
            continue
        if source.startswith("--", at):
            shape = re.match(r"\[(=*)\[", source[at + 2:])
            if shape:
                end = source.find("]" + shape[1] + "]", at + 2 + shape.end())
                if end < 0:
                    raise ValueError("unclosed comment")
                at = end + len(shape[1]) + 2
            else:
                end = source.find("\n", at)
                at = len(source) if end < 0 else end + 1
            continue
        start = at
        if source[at] in "'\"":
            quote = source[at]
            at += 1
            while at < len(source):
                char = source[at]
                at += 1
                if char == quote:
                    break
                if char == "\\":
                    if at >= len(source):
                        raise ValueError("truncated escape")
                    escape = source[at]
                    at += 1
                    if escape == "z":
                        while at < len(source) and source[at] in " \t\r\n\v\f":
                            at += 1
                    elif escape == "\r" and source[at:at + 1] == "\n":
                        at += 1
                elif char in "\r\n":
                    raise ValueError("raw newline in short string")
            else:
                raise ValueError("unclosed quote")
            result.append(Token(source[start:at], start, at, True))
        else:
            shape = re.match(r"\[(=*)\[", source[at:])
            if shape:
                close = "]" + shape[1] + "]"
                end = source.find(close, at + shape.end())
                if end < 0:
                    raise ValueError("unclosed long string")
                at = end + len(close)
                result.append(Token(source[start:at], start, at, True))
            else:
                match = LEX.match(source, at)
                if not match:
                    raise ValueError("invalid token")
                at = match.end()
                result.append(Token(match[0], start, at))
        if len(result) > MAX_TOKENS:
            raise ValueError("token budget")
    return result

def unquote(text: str) -> bytes:
    if len(text) < 2 or text[0] not in "'\"" or text[-1] != text[0]:
        raise ValueError("expected short literal")
    at, out = 1, bytearray()
    simple = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11}
    while at < len(text) - 1:
        char = text[at]
        at += 1
        if char != "\\":
            if char in "\r\n":
                raise ValueError("raw newline")
            out.extend(char.encode())
            continue
        char = text[at]
        at += 1
        if char in simple:
            out.append(simple[char])
        elif char in "'\"\\":
            out.append(ord(char))
        elif char.isascii() and char.isdigit():
            digits = char
            while len(digits) < 3 and at < len(text) - 1 and text[at].isascii() and text[at].isdigit():
                digits += text[at]
                at += 1
            if int(digits) > 255:
                raise ValueError("invalid decimal byte")
            out.append(int(digits))
        elif char == "x":
            digits = text[at:at + 2]
            if not re.fullmatch("[0-9a-fA-F]{2}", digits):
                raise ValueError("invalid hex byte")
            at += 2
            out.append(int(digits, 16))
        elif char == "z":
            while text[at:at + 1] and text[at] in " \t\r\n\v\f":
                at += 1
        elif char in "\r\n":
            if char == "\r" and text[at:at + 1] == "\n":
                at += 1
            out.append(10)
        else:
            raise ValueError("unsupported escape")
    return bytes(out)

def layout(items: list[Token]) -> str:
    output, row = [], []
    for token in items:
        word = token.text
        if not token.string and word in {"else", "elseif", "end", "until", "return"} and row:
            output.append(" ".join(row))
            row = []
        row.append(word)
        if not token.string and word in {";", "then", "do", "else", "end"}:
            output.append(" ".join(row))
            row = []
    if row:
        output.append(" ".join(row))
    return "\n".join(output) + "\n"

def function_end(items: list[Token], start: int) -> int:
    stack = [["function", False]]
    for at in range(start + 1, len(items)):
        token = items[at]
        if token.string:
            continue
        word = token.text
        if word in {"function", "if", "repeat"}:
            stack.append([word, False])
        elif word in {"for", "while"}:
            stack.append([word, True])
        elif word == "do":
            if stack[-1][1]:
                stack[-1][1] = False
            else:
                stack.append([word, False])
        elif word in {"end", "until"}:
            if word == "until" and stack[-1][0] != "repeat":
                raise ValueError("unexpected until")
            stack.pop()
            if not stack:
                return at
        if len(stack) > 96:
            raise ValueError("function nesting budget")
    raise ValueError("unclosed function")

def inspect() -> None:
    raw = (ROOT / "target.original.lua").read_bytes()
    source = raw.decode()
    ts = tokens(source)
    ignore, fragments = {}, {}
    for name in ["_pc0", "_pc1", "_pc2", "_pc3"]:
        found = [i + 3 for i in range(len(ts) - 3)
                 if [t.text for t in ts[i:i + 3]] == ["local", name, "="]]
        if len(found) != 1 or not ts[found[0]].string:
            raise ValueError("missing/ambiguous fragment " + name)
        index = found[0]
        fragments[name] = {"length": len(unquote(ts[index].text)), "literal_token": index}
        ignore[index] = "PAYLOAD:" + name
    normalized = "\n".join(ignore.get(i, t.text) for i, t in enumerate(ts)).encode()
    out = ROOT / "diagnostics"
    out.mkdir(exist_ok=True)
    (out / "wrapper-normalized.txt").write_bytes(normalized)
    masked = [Token(ignore.get(i, t.text), t.start, t.end, t.string) for i, t in enumerate(ts)]
    (out / "wrapper.tokens.txt").write_text(layout(masked))
    functions = []
    for at, token in enumerate(ts):
        if token.string or token.text != "function":
            continue
        begin, label = None, None
        if at >= 2 and ts[at - 1].text == "=" and re.fullmatch("[A-Za-z_][A-Za-z_0-9]*", ts[at - 2].text):
            begin, label = at - 2, ts[at - 2].text
        elif at >= 5 and ts[at - 1].text == "=" and ts[at - 2].text == "]" and ts[at - 4].text == "[":
            begin, label = at - 5, ts[at - 5].text + "_" + ts[at - 3].text
        if label and re.fullmatch("[A-Za-z_][A-Za-z_0-9]*", label):
            end = function_end(ts, at)
            (out / (label + ".txt")).write_text(layout(masked[begin:end + 1]))
            functions.append({"name": label, "first_token": begin, "last_token": end,
                              "byte_start": len(source[:ts[begin].start].encode()),
                              "byte_end": len(source[:ts[end].end].encode())})
    report = {"source_sha256": hashlib.sha256(raw).hexdigest(), "tokens": len(ts),
              "wrapper_sha256": hashlib.sha256(normalized).hexdigest(), "fragments": fragments,
              "functions": functions, "executed": False}
    (out / "fingerprint.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "functions"}, indent=2))
    print("Functions:", ", ".join(f["name"] for f in functions))

if __name__ == "__main__":
    inspect()
