import csv
import re
from pathlib import Path
from datetime import datetime


# Finds headers such as:
# header[opcode=101 counter=162 ver=0.0 size=116 timestamp=1793170876568]
HEADER_PATTERN = re.compile(
    r"header\s*\[([^\]]*)\]",
    re.IGNORECASE
)

# Finds key=value pairs inside the header.
FIELD_PATTERN = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(\"[^\"]*\"|'[^']*'|[^\s]+)"
)


def parse_header(header_text):
    """Extract key=value fields from the header."""
    fields = {}

    for match in FIELD_PATTERN.finditer(header_text):
        key = match.group(1)
        value = match.group(2).strip()

        # Remove matching quotes around values.
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("'", '"')
        ):
            value = value[1:-1]

        fields[key] = value

    return fields


def split_messages(text):
    """
    Split the log at each header[opcode=...] occurrence.
    Each message includes its header and all text up to the next header.
    """
    matches = list(HEADER_PATTERN.finditer(text))

    if not matches:
        return [], text

    messages = []

    # Preserve any text before the first message separately.
    preamble = text[:matches[0].start()]

    for index, match in enumerate(matches):
        start = match.start()

        if index + 1 < len(matches):
            end = matches[index + 1].start()
        else:
            end = len(text)

        raw_message = text[start:end]
        header_text = match.group(1)
        fields = parse_header(header_text)

        opcode = fields.get("opcode", "unknown")

        messages.append({
            "opcode": str(opcode),
            "fields": fields,
            "raw_message": raw_message
        })

    return messages, preamble


def write_csv(output_path, messages):
    """Write messages to CSV, retaining the full raw message."""
    field_names = [
        "message_number",
        "opcode",
        "header_fields",
        "raw_message"
    ]

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=field_names
        )
        writer.writeheader()

        for message_number, message in enumerate(messages, start=1):
            writer.writerow({
                "message_number": message_number,
                "opcode": message["opcode"],
                "header_fields": " ".join(
                    f"{key}={value}"
                    for key, value in message["fields"].items()
                ),
                "raw_message": message["raw_message"]
            })


def main():
    input_path_text = input(
        "Enter the full path of your telemetry .txt file: "
    ).strip().strip('"')

    if not input_path_text:
        print("No input file path entered.")
        return

    input_path = Path(input_path_text)

    if not input_path.is_file():
        print(f"\nInput file not found:\n{input_path}")
        print("Check the path and try again.")
        return

    try:
        text = input_path.read_text(
            encoding="utf-8-sig",
            errors="replace"
        )
    except OSError as error:
        print(f"Could not read the input file: {error}")
        return

    messages, preamble = split_messages(text)

    if not messages:
        print("No headers like header[opcode=101] were found.")
        print("The script did not create any CSV files.")
        return

    # Create a separate output folder beside the input file.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_folder = input_path.parent / f"CSV_Output_{timestamp}"

    try:
        output_folder.mkdir(parents=True, exist_ok=False)

        # Save a copy of the complete source text.
        source_copy = output_folder / "source_text.txt"
        source_copy.write_text(text, encoding="utf-8")

        # Save text appearing before the first message header, if any.
        if preamble.strip():
            (output_folder / "preamble.txt").write_text(
                preamble,
                encoding="utf-8"
            )

        # Save every message in original order.
        write_csv(
            output_folder / "all_messages.csv",
            messages
        )

        # Save one CSV per opcode. Repeated opcodes remain separate rows.
        messages_by_opcode = {}

        for message in messages:
            opcode = message["opcode"]
            messages_by_opcode.setdefault(opcode, []).append(message)

        for opcode, opcode_messages in messages_by_opcode.items():
            safe_opcode = re.sub(r"[^A-Za-z0-9_-]", "_", opcode)
            output_path = output_folder / f"opcode_{safe_opcode}.csv"
            write_csv(output_path, opcode_messages)

    except OSError as error:
        print(f"Could not create output files: {error}")
        return

    print(f"\nFinished. Found {len(messages)} messages.")
    print(f"Found {len(messages_by_opcode)} unique opcodes.")
    print(f"Output folder:\n{output_folder}")


if __name__ == "__main__":
    main()
