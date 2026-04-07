import io
import os
import sys
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from contextlib import redirect_stdout
import requests


def ensure_client_import():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    import client as im_client  # type: ignore[import]

    return im_client


class IMGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("COMP3334 Secure IM GUI")
        self.geometry("700x500")

        self.im_client = ensure_client_import()

        # Server label
        self.server_var = tk.StringVar(value=os.environ.get("IM_SERVER", self.im_client.SERVER))
        server_frame = tk.Frame(self)
        server_frame.pack(fill="x", padx=5, pady=5)
        tk.Label(server_frame, text="Server:").pack(side="left")
        tk.Entry(server_frame, textvariable=self.server_var, width=50).pack(side="left", padx=5)
        tk.Button(server_frame, text="Apply", command=self.apply_server).pack(side="left")

        # Buttons frame
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill="x", padx=5, pady=5)

        def add_btn(text, cmd):
            tk.Button(btn_frame, text=text, command=cmd).pack(side="left", padx=2, pady=2)

        add_btn("Register", self.do_register)
        add_btn("Login", self.do_login)
        add_btn("Logout", self.do_logout)
        add_btn("Add Friend", self.do_add_friend)
        add_btn("Friend Requests", self.do_friend_requests)
        add_btn("Respond Request", self.do_respond_request)
        add_btn("Sync Key", self.do_sync_key)
        add_btn("Verify Peer", self.do_verify_peer)
        add_btn("Send Msg", self.do_send_msg)
        add_btn("Pull Msgs", self.do_pull)
        add_btn("Conversations", self.do_conversations)

        # Output area
        self.output = scrolledtext.ScrolledText(self, state="disabled", wrap="word")
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        self.log("Ready. Use buttons to interact with server.")

    def apply_server(self):
        server = self.server_var.get().strip()
        if not server:
            messagebox.showerror("Error", "Server URL cannot be empty.")
            return
        os.environ["IM_SERVER"] = server
        self.im_client.SERVER = server
        self.log(f"Server set to {server}")

    def log(self, text: str):
        self.output.configure(state="normal")
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def run_action(self, label, func, *args, **kwargs):
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                func(*args, **kwargs)
        except requests.HTTPError as exc:
            detail = ""
            try:
                data = exc.response.json()
                detail = data.get("detail", "")
            except Exception:  # noqa: BLE001
                detail = exc.response.text if exc.response is not None else ""
            self.log(f"[{label}] HTTP ERROR: {exc}")
            if detail:
                self.log(f"[{label}] DETAIL: {detail}")
            return
        except Exception as exc:  # noqa: BLE001
            self.log(f"[{label}] ERROR: {exc}")
            return
        out = buf.getvalue().strip()
        if out:
            self.log(f"[{label}] OUTPUT:\n{out}")
        else:
            self.log(f"[{label}] Done (no output).")

    def ask(self, prompt: str, initial: str = "") -> str | None:
        value = simpledialog.askstring("Input", prompt, initialvalue=initial, parent=self)
        if value is None:
            return None
        return value.strip()

    # Actions
    def do_register(self):
        username = self.ask("Username")
        if not username:
            return
        password = self.ask("Password")
        if password is None:
            return
        self.run_action("Register", self.im_client.register, username, password)

    def do_login(self):
        username = self.ask("Username")
        if not username:
            return
        password = self.ask("Password")
        if password is None:
            return
        otp = self.ask("OTP (6 digits)")
        if otp is None:
            return
        self.run_action("Login", self.im_client.login, username, password, otp)

    def do_logout(self):
        self.run_action("Logout", self.im_client.logout)

    def do_add_friend(self):
        user = self.ask("Username to send friend request to")
        if not user:
            return
        self.run_action("Add Friend", self.im_client.add_friend, user)

    def do_friend_requests(self):
        limit = self.ask("Limit (default 20)", "20") or "20"
        offset = self.ask("Offset (default 0)", "0") or "0"
        try:
            self.run_action("Friend Requests", self.im_client.friend_requests, int(limit), int(offset))
        except ValueError:
            messagebox.showerror("Error", "Limit/offset must be integers.")

    def do_respond_request(self):
        rid = self.ask("Request ID to respond to")
        if not rid:
            return
        action = self.ask("Action (accept/decline)", "accept")
        if not action:
            return
        try:
            self.run_action("Respond Request", self.im_client.respond_request, int(rid), action)
        except ValueError:
            messagebox.showerror("Error", "Request ID must be integer.")

    def do_sync_key(self):
        peer = self.ask("Peer username to sync key with")
        if not peer:
            return
        self.run_action("Sync Key", self.im_client.sync_peer_key, peer)

    def do_verify_peer(self):
        peer = self.ask("Peer username to verify")
        if not peer:
            return
        self.run_action("Verify Peer", self.im_client.verify_peer, peer)

    def do_send_msg(self):
        to_user = self.ask("Send to (peer username)")
        if not to_user:
            return
        text = self.ask("Message text")
        if text is None:
            return
        ttl = self.ask("TTL seconds (default 60)", "60") or "60"
        try:
            self.run_action("Send Message", self.im_client.send_message, to_user, text, int(ttl))
        except ValueError:
            messagebox.showerror("Error", "TTL must be integer.")

    def do_pull(self):
        limit = self.ask("Limit (default 20)", "20") or "20"
        offset = self.ask("Offset (default 0)", "0") or "0"
        try:
            self.run_action("Pull Messages", self.im_client.pull, int(limit), int(offset))
        except ValueError:
            messagebox.showerror("Error", "Limit/offset must be integers.")

    def do_conversations(self):
        limit = self.ask("Limit (default 20)", "20") or "20"
        offset = self.ask("Offset (default 0)", "0") or "0"
        try:
            self.run_action("Conversations", self.im_client.list_conversations_paged, int(limit), int(offset))
        except ValueError:
            messagebox.showerror("Error", "Limit/offset must be integers.")


def main():
    app = IMGui()
    app.mainloop()


if __name__ == "__main__":
    main()

