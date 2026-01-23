Following up on the CMD tool, I decided to create a more user-friendly GUI version. It makes editing the ESKONF (Output Stage Configuration) much more intuitive, especially for those who aren't comfortable with manual bit-shifting in Hex editors.

Key Features:
- Automatic Scanning: The tool automatically scans the BIN file for ESKONF tables (searches for the AA FF 00 pattern with strict validation to avoid false positives).
- Visual Interface: Clearly labels all 28 components (Injectors, Coils, N75, SAI, etc.) across 7 bytes.
- Quick Presets: One-click buttons to disable common components like KAT (LSHHK), SAI, N249, EVAP, or VVT.
- Extended Search: Optional mode for earlier ECUs or previously modified files (toggles FF FF 00 search).
- Manual HEX Entry: You can paste a 14-character HEX string to decode and modify it manually.

How to use:
Load your BIN file or enter HEX code manually
Modify settings using the dropdowns or presets.
Save the modified BIN or copy new HEX code

IMPORTANT: This tool does NOT fix checksums. You must use ME7Sum or a similar tool before flashing.

Source code: Python script for those who want to review or improve the code (requires customtkinter).
