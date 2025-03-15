# Volvo/Geely VBF Firmware Extractor

Python script for extracting firmware from Volvo/Geely VBF files.

Based on [consp/vbfdecode](https://github.com/consp/vbfdecode)

## Features
- Support for VBF v2.6
- VBF file format parsing
- Firmware binary extraction

## Requirements
- Python 3.6+

## Usage
```bash
usage: vbf_extractor.py [-h] [-f FILE] [-d DST]

Python script for extracting firmware from Volvo/Geely VBF files.

options:
  -h, --help       show this help message and exit
  -f, --file FILE  Firmware file path
  -d, --dst DST    Output directory
```

## Output
```bash
VBF v2.6
Description: 
Software part: 6608384969  version: C  type: EXE
Network: 0x00000000
Data Format Identifier: 0x00000000
Checksum: 0x81041F96
Verification block start: 0x0006001F
Verification block length: 0x000000CC
Verification block root hash: 50297771048413737912187916691747667825667959033159328062736259294583250754469
Verification block hash: XXXXXXXXXXXXXXXXXX
Software signature: XXXXXXXXXXXXXXXXXXXXXX
ECU address: 0x00001002
Frame_format:
Erase frames:
	0x84 (0x268435456)
	0x8 (0x12582924)
Data blobs:
Location: 0x00060000, Size: 0x00800000, Checksum: 0x46a7
Location: 0x00060001, Size: 0x04000000, Checksum: 0x75e7
Location: 0x00060002, Size: 0x04000000, Checksum: 0x8818
Location: 0x00060003, Size: 0x04000000, Checksum: 0x333e
Location: 0x00060004, Size: 0x0207425F, Checksum: 0x7bc5
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.
