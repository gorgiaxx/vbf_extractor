import re
import json
from typing import Dict, Any, List


def parse_config_file(content: str) -> Dict[str, Any]:
    content = remove_comments(content)

    tokens = tokenize(content)
    result = {}

    i = 0
    while i < len(tokens):
        if tokens[i]['type'] == 'identifier' and i + 2 < len(tokens) and tokens[i+1]['type'] == '=':
            key = tokens[i]['value']

            # Process block structure (e.g. header { ... })
            if i + 3 < len(tokens) and tokens[i+2]['type'] == 'identifier' and tokens[i+3]['type'] == '{':
                block_name = tokens[i+2]['value']
                # Find the closing brace
                brace_count = 1
                start_idx = i + 4
                end_idx = start_idx

                while end_idx < len(tokens) and brace_count > 0:
                    if tokens[end_idx]['type'] == '{':
                        brace_count += 1
                    elif tokens[end_idx]['type'] == '}':
                        brace_count -= 1
                    end_idx += 1

                if brace_count == 0:
                    # Recursively parse block content
                    block_tokens = tokens[start_idx:end_idx-1]
                    result[block_name] = parse_block_tokens(block_tokens)
                    i = end_idx
                    continue

            # Process normal key-value pairs
            value_tokens = []
            i += 2  # Skip the "=" symbol

            # Collect all tokens until the semicolon
            while i < len(tokens) and tokens[i]['type'] != ';':
                value_tokens.append(tokens[i])
                i += 1

            if i < len(tokens) and tokens[i]['type'] == ';':
                result[key] = parse_value_tokens(value_tokens)
                i += 1
                continue
        i += 1

    return result


def parse_block_tokens(tokens: List[Dict]) -> Dict[str, Any]:
    result = {}
    i = 0
    while i < len(tokens):
        if tokens[i]['type'] == 'identifier' and i + 2 < len(tokens) and tokens[i+1]['type'] == '=':
            key = tokens[i]['value']
            value_tokens = []
            i += 2  # Skip the "=" symbol
            # Collect all tokens until the semicolon
            while i < len(tokens) and tokens[i]['type'] != ';':
                value_tokens.append(tokens[i])
                i += 1
            if i < len(tokens) and tokens[i]['type'] == ';':
                result[key] = parse_value_tokens(value_tokens)
                i += 1
                continue
        i += 1
    return result


def parse_value_tokens(tokens: List[Dict]) -> Any:
    if not tokens:
        return None

    if len(tokens) == 1:
        token = tokens[0]
        if token['type'] == 'number':
            return float(token['value']) if '.' in token['value'] else int(token['value'])
        elif token['type'] == 'hex':
            return int(token['value'], 16)
        elif token['type'] == 'string':
            return token['value']
        elif token['type'] == 'identifier':
            if token['value'].lower() == 'true':
                return True
            elif token['value'].lower() == 'false':
                return False
            else:
                return token['value']

    if tokens[0]['type'] == '{' and tokens[-1]['type'] == '}':
        inner_tokens = tokens[1:-1]
        return parse_array_tokens(inner_tokens)

    if tokens[0]['type'] == '{' and any(t['type'] == 'string' for t in tokens):
        json_str = ''.join(t['value'] if t['type'] ==
                           'string' else t['raw'] for t in tokens)
        try:
            return json.loads(json_str)
        except:
            pass

    combined = ''.join(t['raw'] for t in tokens).strip()

    return combined


def parse_array_tokens(tokens: List[Dict]) -> List[Any]:
    result = []
    current_item = []
    brace_level = 0

    for token in tokens:
        if token['type'] == ',' and brace_level == 0:
            if current_item:
                result.append(parse_value_tokens(current_item))
                current_item = []
        else:
            if token['type'] == '{':
                brace_level += 1
            elif token['type'] == '}':
                brace_level -= 1
            current_item.append(token)

    if current_item:
        result.append(parse_value_tokens(current_item))

    return result


def tokenize(content: str) -> List[Dict]:
    tokens = []
    i = 0

    while i < len(content):
        char = content[i]

        if char.isspace():
            i += 1
            continue

        if char.isalpha() or char == '_':
            start = i
            while i < len(content) and (content[i].isalnum() or content[i] == '_'):
                i += 1
            value = content[start:i]
            tokens.append({'type': 'identifier', 'value': value, 'raw': value})
            continue

        # Number
        if char.isdigit() or (char == '-' and i+1 < len(content) and content[i+1].isdigit()):
            start = i
            i += 1
            # Detect hexadecimal
            if char == '0' and i < len(content) and content[i].lower() == 'x':
                i += 1
                while i < len(content) and (content[i].isdigit() or content[i].lower() in 'abcdef'):
                    i += 1
                value = content[start:i]
                tokens.append({'type': 'hex', 'value': value, 'raw': value})
            else:
                # Process normal number
                has_dot = False
                while i < len(content) and (content[i].isdigit() or (content[i] == '.' and not has_dot)):
                    if content[i] == '.':
                        has_dot = True
                    i += 1
                value = content[start:i]
                tokens.append({'type': 'number', 'value': value, 'raw': value})
            continue

        # String
        if char in ['"', "'"]:
            quote = char
            start = i
            i += 1
            while i < len(content) and content[i] != quote:
                if content[i] == '\\' and i+1 < len(content):
                    i += 2
                else:
                    i += 1

            if i < len(content):  # Found the end quote
                i += 1  # Include the end quote
                raw = content[start:i]
                value = raw[1:-1]  # Remove the quotes
                tokens.append({'type': 'string', 'value': value, 'raw': raw})
            continue

        if char in ['{', '}', '=', ';', ',']:
            tokens.append({'type': char, 'value': char, 'raw': char})
            i += 1
            continue

        tokens.append({'type': 'unknown', 'value': char, 'raw': char})
        i += 1

    return tokens


def remove_comments(content: str) -> str:
    # Remove multiline comments (/* ... */)
    multiline_pattern = re.compile(r'/\*.*?\*/', re.DOTALL)
    content = multiline_pattern.sub('', content)

    # Remove single line comments (// ...)
    lines = []
    for line in content.split('\n'):
        comment_pos = line.find('//')
        if comment_pos >= 0:
            line = line[:comment_pos]
        lines.append(line)

    return '\n'.join(lines)


class VBF:
    def __init__(self, data):
        if not isinstance(data, bytes):
            raise TypeError("Requires binary input")

        version_tag = b"vbf_version"
        version_start = data.find(version_tag)
        if version_start == -1:
            raise ValueError("Version tag not found")

        config_end = self.find_config_tail(data)
        if config_end == -1:
            raise ValueError("Config end not found")
        binary_offset = config_end + 1
        config_binary = data[:binary_offset]
        partition_binary = data[binary_offset:]
        config_str = config_binary.decode()
        self.config = parse_config_file(config_str)

        self.version = self.config.get("vbf_version", "")
        self.sw_part = self.config.get("sw_part_number", "")
        self.sw_part_type = self.config.get("sw_part_type", "")
        self.sw_version = self.config.get("sw_version", "")
        self.description = self.config.get("description", "")
        self.network = self.config.get("network", 0x00)
        self.data_format_identifier = self.config.get(
            "data_format_identifier", 0x00)
        self.ecu_address = self.config.get("ecu_address", 0x00)
        self.verification_block_start = self.config.get(
            "verification_block_start", 0x00)
        self.frame_format = self.config.get("frame_format", "")
        self.erase = self.config.get("erase", [])
        self.checksum = self.config.get("file_checksum", "")
        self.verification_block_start = self.config.get(
            "verification_block_start", 0x00)
        self.verification_block_length = self.config.get(
            "verification_block_length", 0x00)
        self.verification_block_root_hash = self.config.get(
            "verification_block_root_hash", "")
        self.verification_block_hash = self.config.get("sw_signature_dev", "")
        self.sw_signature = self.config.get("sw_signature", "")
        self.raw = data

        self.partitions = []
        while len(partition_binary) > 0:
            location = int.from_bytes(partition_binary[:4], 'big')
            size = int.from_bytes(partition_binary[4:8], 'big')
            data = partition_binary[8:8+size]
            checksum = partition_binary[8+size:8+size+2]
            partition_binary = partition_binary[8+size+2:]
            # print("Offset: 0x{:08X}, Location: 0x{:08X}, Size: 0x{:08X}, Data Offset: 0x{:08X}".format(binary_offset,  location, size, binary_offset + 8))
            binary_offset += 8+size+2
            if location != self.verification_block_start:
                self.partitions.append((location, data, checksum))
    
    def find_config_tail(self, data: bytes):
        start = 0x7b
        end = 0x7d
        level = 1
        end_idx = -1
        start_idx = data.find(start)
        if start_idx == -1:
            return -1
        else:
            for i in range(start_idx + 1, len(data)):
                if data[i] == start:
                    print(data[i:i+10])
                    level += 1
                elif data[i] == end:
                    level -= 1
                if level == 0:
                    end_idx = i
                    break
        return end_idx

    def __str__(self):
        string = f"VBF v{self.version}\n"
        string += f"Description: {self.description}\n"
        string += f"Software part: {self.sw_part}  version: {self.sw_version}  type: {self.sw_part_type}\n"
        string += f"Network: 0x{self.network:08X}\n"
        string += f"Data Format Identifier: 0x{self.data_format_identifier:08X}\n"
        string += f"Checksum: 0x{self.checksum:08X}\n"
        string += f"Verification block start: 0x{self.verification_block_start:08X}\n"
        string += f"Verification block length: 0x{self.verification_block_length:08X}\n"
        string += f"Verification block root hash: {self.verification_block_root_hash}\n"
        string += f"Verification block hash: {self.verification_block_hash}\n"
        string += f"Software signature: {self.sw_signature}\n"
        string += f"ECU address: 0x{self.ecu_address:08X}\n"
        string += f"Frame_format:{self.frame_format}\n"
        string += "Erase frames:\n"
        for x in self.erase:
            string += f"\t0x{x[1]} (0x{x[0]})\n"
        string += "Data blobs:\n"
        for i in self.partitions:
            string += f"Location: 0x{i[0]:08X}, Size: 0x{len(i[1]):08X}, Checksum: 0x{i[2].hex()}\n"
        return string

    def dump(self, dst, show_progress=False):
        import os
        os.makedirs(dst, exist_ok=True)
        for x in self.partitions:
            if show_progress:
                print(f"Extracting {x[0]:08X}.bin ")
            filename = f"{x[0]:08X}.bin".replace(" ", "")
            with open(os.path.join(dst, filename), "wb") as f:
                f.write(x[1])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Python script for extracting firmware from Volvo/Geely VBF files.")
    parser.add_argument('-f', '--file', type=str, help='Firmware file path')
    parser.add_argument('-d', '--dst', type=str, help='Output directory')
    args = parser.parse_args()
    if args.file:
        with open(args.file, 'rb') as f:
            vbf = VBF(f.read())
        print(vbf)
        # print(json.dumps(vbf.config, indent=4))
        if args.dst:
            vbf.dump(args.dst, show_progress=True)
    else:
        parser.print_help()
