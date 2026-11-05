
import csv
import re
import sys
from pathlib import Path
from collections import OrderedDict


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

UNITS = (
    "deg", "m/s", "km/h", "kts", "km", "ft", "mach", "m"
)

TIMESTAMP_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]"
)

HEADER_RE = re.compile(r"header\[(.*?)\]", re.DOTALL)

KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Match a key followed by = or [.
# Values are parsed separately so nested blocks are supported.
KEY_VALUE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*="
)

INDEXED_RE = re.compile(r"(\d+)\s*[:(]\s*")


# ---------------------------------------------------------
# Cleaning
# ---------------------------------------------------------

def clean_value(value):
    """Remove units, delimiters, quotes, and trailing commas."""

    value = value.strip()

    # Remove bracketed units, including units with slashes.
    value = re.sub(
        r"\[(?:deg|m/s|km/h|kts|km|ft|mach|m)\]",
        "",
        value,
        flags=re.IGNORECASE
    )

    value = value.strip()

    # Remove surrounding syntax.
    value = value.strip("{}[](),\"' \t\r\n")

    # Remove trailing commas and spaces.
    value = value.rstrip(",").strip()

    return value


def is_key_start(text, position):
    """Check whether a new key begins at a position."""

    match = KEY_RE.match(text, position)

    if not match:
        return False

    end = match.end()

    while end < len(text) and text[end].isspace():
        end += 1

    return end < len(text) and text[end] in "=[:"


# ---------------------------------------------------------
# Lexical parser
# ---------------------------------------------------------

def parse_pairs(text):
    """
    Parse key=value pairs from a text block.

    Supports:
        lat=13.2
        velocity[N,E,U]=[1,2,3]
        combat_emergency={ew=1 sensor=0}
        radioData[legacyFreq1=[D1=1 D2=2]]
    """

    result = OrderedDict()

    i = 0
    length = len(text)

    while i < length:
        match = KEY_RE.match(text, i)

        if not match:
            i += 1
            continue

        key = match.group()
        pos = match.end()

        while pos < length and text[pos].isspace():
            pos += 1

        # Skip standalone words.
        if pos >= length or text[pos] not in "=[":
            i = match.end()
            continue

        # -------------------------------------------------
        # Handle key=[N,E,U] style keys.
        # -------------------------------------------------

        if text[pos] == "[":
            close = find_matching(text, pos)

            if close == -1:
                i = pos + 1
                continue

            contents = text[pos + 1:close].strip()

            # If this is a vector such as velocity[N,E,U]=...
            # the following '=' identifies it as a key.
            after = close + 1

            while after < length and text[after].isspace():
                after += 1

            if after < length and text[after] == "=":
                value_start = after + 1

                value, next_pos = read_value(text, value_start)

                components = [
                    x.strip()
                    for x in contents.split(",")
                ]

                values = [
                    x.strip()
                    for x in value.strip("[]").split(",")
                ]

                for component, component_value in zip(
                    components, values
                ):
                    result[f"{key}_{component}"] = clean_value(
                        component_value
                    )

                i = next_pos
                continue

            # Otherwise this is a nested block.
            result[key] = parse_pairs(contents)
            i = close + 1
            continue

        # -------------------------------------------------
        # Handle key=value.
        # -------------------------------------------------

        if text[pos] == "=":
            value_start = pos + 1

            value, next_pos = read_value(
                text, value_start
            )

            result[key] = clean_value(value)

            i = next_pos
            continue

        i += 1

    return result


def find_matching(text, start):
    """Find matching bracket, respecting nested brackets."""

    pairs = {
        "[": "]",
        "{": "}",
        "(": ")"
    }

    opening = text[start]

    if opening not in pairs:
        return -1

    closing = pairs[opening]

    depth = 0
    quote = None

    for i in range(start, len(text)):
        char = text[i]

        if quote:
            if char == quote:
                quote = None
            continue

        if char in "\"'":
            quote = char
            continue

        if char == opening:
            depth += 1

        elif char == closing:
            depth -= 1

            if depth == 0:
                return i

    return -1


def read_value(text, start):
    """
    Read a value until the next top-level key.

    Nested blocks are kept together.
    """

    i = start
    length = len(text)

    while i < length and text[i].isspace():
        i += 1

    if i >= length:
        return "", length

    # Empty value: key= nextKey=value
    if is_key_start(text, i):
        return "", i

    depth = 0
    quote = None

    while i < length:
        char = text[i]

        if quote:
            if char == quote:
                quote = None
            i += 1
            continue

        if char in "\"'":
            quote = char
            i += 1
            continue

        if char in "[{(":
            depth += 1

        elif char in "]})":
            depth -= 1

        # A new key at depth zero ends the current value.
        elif depth == 0 and char.isspace():
            next_pos = i

            while (
                next_pos < length
                and text[next_pos].isspace()
            ):
                next_pos += 1

            if is_key_start(text, next_pos):
                return text[start:i].strip(), next_pos

        i += 1

    return text[start:length].strip(), length


# ---------------------------------------------------------
# Message parsing
# ---------------------------------------------------------

def flatten(data, prefix=""):
    """Flatten nested dictionaries into CSV column names."""

    result = OrderedDict()

    for key, value in data.items():
        name = f"{prefix}_{key}" if prefix else key

        if isinstance(value, dict):
            result.update(flatten(value, name))

        else:
            result[name] = value

    return result


def parse_header(header_text):
    """Parse the header block."""

    return parse_pairs(header_text)


def extract_indexed_items(text):
    """
    Extract indexed entities.

    Example:
        0:(globalId=... lat=...)
        1:(globalId=... lat=...)
    """

    items = OrderedDict()

    matches = list(INDEXED_RE.finditer(text))

    for index, match in enumerate(matches):
        start = match.end()

        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(text)
        )

        block = text[start:end].strip()

        # Remove one outer wrapper.
        if block.startswith("(") or block.startswith("["):
            closing = ")" if block.startswith("(") else "]"

            if block.endswith(closing):
                block = block[1:-1]

        items[int(match.group(1))] = parse_pairs(block)

    return items


def parse_message(message):
    """Parse one complete telemetry message."""

    lines = message.splitlines()

    metadata = OrderedDict()

    # -----------------------------------------------------
    # Timestamp
    # -----------------------------------------------------

    if lines:
        match = TIMESTAMP_RE.match(lines[0])

        if match:
            metadata["log_timestamp"] = match.group(1)

    # -----------------------------------------------------
    # Process name, log level, and parser name
    # -----------------------------------------------------

    for line in lines:
        parts = re.findall(r"\[([^\]]*)\]", line)

        if len(parts) >= 4 and TIMESTAMP_RE.match(line):
            metadata["process"] = parts[1]
            metadata["log_level"] = parts[3]

        if len(parts) >= 4 and not TIMESTAMP_RE.match(line):
            parser_name = parts[-1]

            if parser_name not in (
                "process", "info", "debug", "warn", "error"
            ):
                metadata["parser_name"] = parser_name

    # -----------------------------------------------------
    # Header
    # -----------------------------------------------------

    header_match = HEADER_RE.search(message)

    header = OrderedDict()

    if header_match:
        header = parse_header(header_match.group(1))

    opcode = header.get("opcode", "")

    if not opcode:
        return None

    row = OrderedDict(metadata)

    # Header fields appear in deterministic order.
    for key in (
        "opcode", "counter", "ver", "size", "timestamp"
    ):
        if key in header:
            row[key] = header[key]

    # Include any additional header parameters.
    for key, value in header.items():
        if key not in row:
            row[key] = value

    # -----------------------------------------------------
    # Parse body
    # -----------------------------------------------------

    body = message

    if header_match:
        body = message[header_match.end():]

    # Remove log metadata and parser names.
    body = re.sub(
        r"^\[[^\]]*\].*$",
        "",
        body,
        flags=re.MULTILINE
    )

    # Remove header itself.
    body = HEADER_RE.sub("", body)

    # -----------------------------------------------------
    # Extract top-level counts.
    # -----------------------------------------------------

    top_level = parse_pairs(body)

    for key in (
        "numTargets",
        "numOfTargets",
        "numNetMem",
        "numMembers"
    ):
        if key in top_level:
            row[key] = top_level[key]

    # -----------------------------------------------------
    # Extract repeating target/member blocks.
    # -----------------------------------------------------

    repeating_names = {
        "nwTargetsPos": "target",
        "targetsStatus": "target",
        "target_data": "target",
        "members_position_data": "member",
    }

    for block_name, prefix in repeating_names.items():
        pattern = re.compile(
            re.escape(block_name) + r"\s*[\[{]"
        )

        match = pattern.search(body)

        if not match:
            continue

        start = match.end() - 1

        end = find_matching(body, start)

        if end == -1:
            continue

        block = body[start + 1:end]

        items = extract_indexed_items(block)

        for index, item in items.items():
            flat = flatten(item)

            for key, value in flat.items():
                row[f"{prefix}[{index}]_{key}"] = value

    # -----------------------------------------------------
    # Parse remaining parameters.
    # -----------------------------------------------------

    # Remove repeating blocks before parsing top-level keys.
    for block_name in repeating_names:
        body = re.sub(
            re.escape(block_name) + r"\s*[\[{].*",
            "",
            body,
            flags=re.DOTALL
        )

    remaining = parse_pairs(body)

    row.update(flatten(remaining))

    return opcode, row


# ---------------------------------------------------------
# Split log into messages
# ---------------------------------------------------------

def split_messages(text):
    """
    Split on timestamp lines.

    Multiline payloads remain together.
    """

    messages = []
    current = []

    for line in text.splitlines():
        if TIMESTAMP_RE.match(line):
            if current:
                messages.append("\n".join(current))

            current = [line]

        elif current:
            current.append(line)

    if current:
        messages.append("\n".join(current))

    return messages


# ---------------------------------------------------------
# CSV output
# ---------------------------------------------------------

def write_csv_files(records, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    for opcode, rows in records.items():

        # Maintain deterministic column order.
        columns = []

        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)

        output_file = output_dir / f"opcode_{opcode}.csv"

        with output_file.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=columns,
                extrasaction="ignore"
            )

            writer.writeheader()

            for row in rows:
                writer.writerow(row)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():
    input_file = Path(
        r"C:\Users\shash\OneDrive\Documents\Downloads\telemetry_photos_transcription.txt"
    )

    output_dir = Path(
        r"C:\Users\shash\OneDrive\Documents\TelemetryCSV"
    )

    if not input_file.is_file():
        print(f"Input file not found: {input_file}")
        return

    text = input_file.read_text(
        encoding="utf-8",
        errors="replace"
    )

    messages = split_messages(text)
    records = OrderedDict()

    for message in messages:
        try:
            parsed = parse_message(message)

            if parsed:
                opcode, row = parsed
                records.setdefault(opcode, []).append(row)

        except Exception as exc:
            print(f"Warning: {exc}")

    write_csv_files(records, output_dir)

    print(f"Processed {len(messages)} messages.")
    print(f"CSV files saved to: {output_dir}")



if __name__ == "__main__":
    main()
