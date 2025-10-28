"""
StickerGuard.exe - USB HID Defense Tool
Detects unknown keyboards, captures input, re-authenticates,
and uses local AI to explain what the device is doing.
"""

import os
import sys
import time
import threading
import queue
import tkinter as tk
from tkinter import messagebox, simpledialog
import getpass
import ctypes
from ctypes import wintypes
import win32api
import win32con
import win32security
import win32com.client
import win32process
import requests
import winreg

# === CONFIG ===
ICON_PATH = os.path.join(os.path.dirname(__file__), "shield.ico")
OLLAMA_MODEL = "llama3"
CAPTURE_SECONDS = 8

# === GLOBALS ===
keystroke_queue = queue.Queue()
allowed = threading.Event()
blocked = threading.Event()
captured_input = ""
hook_id = None

# === AUTO-START ===
def enable_autostart():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        exe_path = sys.executable if getattr(sys, 'frozen', False) else __file__
        winreg.SetValueEx(key, "StickerGuard", 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(key)
    except:
        pass

# === RE-AUTHENTICATE ===
def reauthenticate():
    root = tk.Tk()
    root.withdraw()
    user = getpass.getuser()
    pwd = simpledialog.askstring("StickerGuard", f"Re-enter password for {user}:", show='*')
    root.destroy()
    if not pwd:
        return False
    try:
        token = win32security.LogonUser(user, None, pwd, win32security.LOGON32_LOGON_INTERACTIVE, win32security.LOGON32_PROVIDER_DEFAULT)
        token.Close()
        return True
    except:
        return False

# === AI SUMMARY ===
def get_ai_summary(cmd):
    try:
        resp = requests.post("http://localhost:11434/api/generate", json={
            "model": OLLAMA_MODEL,
            "prompt": f"Summarize in 1 sentence what this Windows command does:\n\n{cmd}",
            "stream": False
        }, timeout=10)
        return resp.json().get("response", "[AI error]").strip()
    except:
        return "[Ollama not running or unreachable]"

# === KEYBOARD HOOK ===
def keyboard_hook(nCode, wParam, lParam):
    global captured_input
    if nCode == win32con.HC_ACTION and wParam in (win32con.WM_KEYDOWN, win32con.WM_SYSKEYDOWN):
        vk = lParam.contents.vk_code
        if 0x30 <= vk <= 0x5A or vk in [0x20, 0x0D, 0x08]:
            shift = win32api.GetKeyState(win32con.VK_SHIFT) & 0x8000
            char = chr(vk)
            if 'a' <= char <= 'z' and shift:
                char = char.upper()
            captured_input += char
            if not allowed.is_set() and not blocked.is_set():
                keystroke_queue.put(char)
    return ctypes.windll.user32.CallNextHookEx(hook_id, nCode, wParam, lParam) if allowed.is_set() else 1

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.LPARAM))

def install_hook():
    global hook_id
    user32 = ctypes.windll.user32
    proc = HOOKPROC(keyboard_hook)
    hook_id = user32.SetWindowsHookExW(win32con.WH_KEYBOARD_LL, proc, 0, 0)

def remove_hook():
    global hook_id
    if hook_id:
        ctypes.windll.user32.UnhookWindowsHookEx(hook_id)
        hook_id = None

# === USB DETECTION ===
def get_usb_keyboards():
    try:
        wmi = win32com.client.GetObject("winmgmts:")
        return [d.PNPDeviceID for d in wmi.InstancesOf("Win32_Keyboard") if "USB" in d.Caption or "HID" in d.Caption]
    except:
        return []

known_keyboards = get_usb_keyboards()

def monitor_usb():
    global known_keyboards
    while True:
        time.sleep(2)
        current = get_usb_keyboards()
        new = [d for d in current if d not in known_keyboards]
        if new and not (allowed.is_set() or blocked.is_set()):
            threading.Thread(target=handle_device, args=(new[0],), daemon=True).start()
            known_keyboards = current

# === HANDLE NEW DEVICE ===
def handle_device(pnp_id):
    global captured_input
    captured_input = ""

    if not reauthenticate():
        messagebox.showerror("StickerGuard", "Authentication failed. Device blocked.")
        blocked.set()
        return

    messagebox.showinfo("StickerGuard", f"New USB keyboard detected.\nCapturing input for {CAPTURE_SECONDS} seconds...")
    install_hook()
    time.sleep(CAPTURE_SECONDS)
    remove_hook()

    if not captured_input.strip():
        messagebox.showinfo("StickerGuard", "No input. Device idle.")
        allowed.set()
        return

    summary = get_ai_summary(captured_input)

    # Decision UI
    root = tk.Tk()
    root.title("StickerGuard - Review Input")
    root.geometry("750x560")
    root.iconbitmap(ICON_PATH)

    tk.Label(root, text="USB Keyboard Input Detected", font=("Arial", 14, "bold")).pack(pady=10)
    tk.Label(root, text="Review and decide:", font=("Arial", 10)).pack()

    frame = tk.Frame(root)
    frame.pack(pady=10, padx=20, fill="both", expand=True)
    text = tk.Text(frame, font=("Consolas", 10), wrap="word")
    text.insert("1.0", captured_input)
    text.config(state="disabled")
    text.pack(side="left", fill="both", expand=True)
    sb = tk.Scrollbar(frame, command=text.yview)
    sb.pack(side="right", fill="y")
    text.config(yscrollcommand=sb.set)

    tk.Label(root, text="AI Summary:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20, pady=(10,0))
    tk.Label(root, text=summary, wraplength=700, bg="#f0f0f0", relief="sunken", padx=10, pady=5).pack(fill="x", padx=20)

    btns = tk.Frame(root)
    btns.pack(pady=15)
    tk.Button(btns, text="ALLOW", bg="green", fg="white", width=15, command=lambda: (allowed.set(), root.destroy())).pack(side="left", padx=10)
    tk.Button(btns, text="BLOCK", bg="red", fg="white", width=15, command=lambda: (blocked.set(), root.destroy())).pack(side="left", padx=10)

    root.mainloop()

# === SYSTEM TRAY ===
def create_tray():
    from PIL import Image
    import pystray
    image = Image.open(ICON_PATH)
    menu = pystray.Menu(
        pystray.MenuItem("Open", lambda: messagebox.showinfo("StickerGuard", "Running in background.")),
        pystray.MenuItem("Exit", lambda: (icon.stop(), os._exit(0)))
    )
    global icon
    icon = pystray.Icon("StickerGuard", image, "StickerGuard Active", menu)
    icon.run()

# === MAIN ===
def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    enable_autostart()
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    threading.Thread(target=create_tray, daemon=True).start()
    threading.Thread(target=monitor_usb, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except:
        remove_hook()

if __name__ == "__main__":
    main()