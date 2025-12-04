import threading
import time
import secrets

# Track active clipboard clear timers
clipboard_timers = {}

# Clear clipboard after a delay using Python subprocess with xclip
def clear_clipboard_after_delay(delay_seconds, clipboard_id=None):
    # This runs in a background thread and clears system-wide clipboard on Linux X11
    def clear_task():
        time.sleep(delay_seconds)
        try:
            current_clipboard_id = clipboard_id if clipboard_id is not None else f"{int(time.time())}_{secrets.token_hex(8)}"

            try:
                import subprocess
                import platform

                if platform.system() == 'Linux':
                    # Clear clipboard using xclip (X11)
                    subprocess.run(['xclip', '-selection', 'clipboard'],
                                 input=b'',
                                 check=True,
                                 timeout=2)
                    print(f"[AegisX] ✓ Clipboard cleared after {delay_seconds} seconds using xclip")
                else:
                    # Fallback to pyperclip for other platforms
                    try:
                        import pyperclip
                        pyperclip.copy('')
                        print(f"[AegisX] ✓ Clipboard cleared after {delay_seconds} seconds using pyperclip")
                    except ImportError:
                        print(f"[AegisX] pyperclip not installed, clipboard clear skipped")
            except FileNotFoundError:
                print(f"[AegisX] xclip not installed. Install with: sudo apt-get install xclip")
            except subprocess.TimeoutExpired:
                print(f"[AegisX] xclip timeout")
            except Exception as e:
                print(f"[AegisX] Failed to clear clipboard: {e}")

            # Remove from tracking
            clipboard_timers.pop(current_clipboard_id, None)
        except Exception as e:
            print(f"[AegisX] Clipboard clear error: {e}")

    # Start thread
    thread = threading.Thread(target=clear_task, daemon=True)
    if clipboard_id is None:
        clipboard_id = f"{int(time.time())}_{secrets.token_hex(8)}"
    clipboard_timers[clipboard_id] = thread
    thread.start()
    return clipboard_id
