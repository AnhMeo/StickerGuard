@echo off
pyinstaller --onefile --windowed --icon=shield.ico --name="StickerGuard" --add-data "stickerguard.ico;." stickerguard.py
echo.
echo Build complete! Check dist\StickerGuard.exe
pause