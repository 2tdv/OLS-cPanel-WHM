#!/usr/bin/python3
"""Translate a cPanel-generated PHP-FPM pool into OLS vhost phpIniOverride lines (G0-D, R-04).
php_admin_* keep administrator precedence in OLS (passed at SYSTEM level); php_value/php_flag
stay user-overridable, matching FPM semantics."""
import re
import sys

LINE = re.compile(r"^\s*(php_admin_value|php_admin_flag|php_value|php_flag)\[([A-Za-z0-9_.]+)\]\s*=\s*(.*?)\s*$")

INI_TRUE = {"on", "yes", "true"}
INI_FALSE = {"off", "no", "false", "none", "null"}
FLAG_TRUE = {"1", "on", "yes", "true"}
FLAG_FALSE = {"0", "off", "no", "false", "none", ""}
TOKEN = re.compile(r"\s*(?:(E_[A-Z_]+)|(\d+)|([|&^~()]))")

def evaluate_constants(expression, constants):
    """Evaluate an INI constant expression such as "E_ALL & ~E_NOTICE" without eval().
    The INI parser does this for php.ini/FPM pools; values passed through OLS are not parsed,
    so a raw expression would become 0 at runtime."""
    tokens, position = [], 0
    while position < len(expression):
        match = TOKEN.match(expression, position)
        if not match or match.end() == position:
            if expression[position:].strip() == "":
                break
            raise ValueError(f"unsupported token in {expression!r}")
        name, number, op = match.groups()
        if name is not None:
            if name not in constants:
                raise ValueError(f"unknown constant {name}")
            tokens.append(int(constants[name]))
        elif number is not None:
            tokens.append(int(number))
        else:
            tokens.append(op)
        position = match.end()

    def parse(index, precedence=0):
        # Precedence (low to high): | ^ & ; unary ~ ; parentheses.
        value, index = unary(index)
        levels = {"|": 1, "^": 2, "&": 3}
        while index < len(tokens) and tokens[index] in levels and levels[tokens[index]] > precedence:
            op = tokens[index]
            right, index = parse(index + 1, levels[op])
            value = value | right if op == "|" else value ^ right if op == "^" else value & right
        return value, index

    def unary(index):
        if index >= len(tokens):
            raise ValueError("unexpected end of expression")
        token = tokens[index]
        if token == "~":
            value, index = unary(index + 1)
            return ~value, index
        if token == "(":
            value, index = parse(index + 1)
            if index >= len(tokens) or tokens[index] != ")":
                raise ValueError("unbalanced parentheses")
            return value, index + 1
        if isinstance(token, int):
            return token, index + 1
        raise ValueError(f"unexpected {token!r}")

    value, index = parse(0)
    if index != len(tokens):
        raise ValueError(f"trailing tokens in {expression!r}")
    return value

def translate(pool_text, constants=None):
    entries = []
    for raw in pool_text.splitlines():
        match = LINE.match(raw)
        if not match:
            continue
        kind, key, value = match.groups()
        quoted = len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'"
        if quoted:
            value = value[1:-1]
        if "\n" in value or "}" in value:
            raise ValueError(f"unsafe value for {key}")
        if kind.endswith("_flag"):
            lowered = value.lower()
            if lowered in FLAG_TRUE:
                value = "1"
            elif lowered in FLAG_FALSE:
                value = "0"
            else:
                raise ValueError(f"invalid flag value for {key}: {value!r}")
        elif not quoted and value.lower() in INI_TRUE | INI_FALSE:
            # The INI parser maps bare boolean words; OLS passes the raw text instead.
            value = "1" if value.lower() in INI_TRUE else ""
        elif re.search(r"\bE_[A-Z_]+\b", value):
            if constants is None:
                raise ValueError(f"{key} uses constants; pass the target PHP's E_* constants")
            value = str(evaluate_constants(value, constants))
        entries.append((kind, key, value))
    return entries

def override_block(entries):
    if not entries:
        return ""
    body = "\n".join(f"{kind} {key} {value}" for kind, key, value in entries)
    return f"phpIniOverride  {{\n{body}\n}}\n"

def suffixes(pool_text):
    match = re.search(r"^\s*security\.limit_extensions\s*=\s*(.+)$", pool_text, re.M)
    if not match:
        return ["php"]
    return [s.lstrip(".") for s in match.group(1).split() if re.fullmatch(r"\.?[A-Za-z0-9]+", s)]

if __name__ == "__main__":
    print(override_block(translate(open(sys.argv[1]).read())), end="")
