import argparse
import os
import sys
import traceback


def main():
    parser = argparse.ArgumentParser(description="COMP3334 Secure IM - Simple UI (terminal menu)")
    parser.add_argument("--server", default=None, help="IM server base URL (e.g., http://127.0.0.1:8000 or https://127.0.0.1:8443)")
    args = parser.parse_args()

    # Ensure we can import `client.py` regardless of where user runs this from.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # Import after we have script_dir available.
    import client as im_client  # noqa: E402

    if args.server:
        os.environ["IM_SERVER"] = args.server
        im_client.SERVER = args.server

    def ask(prompt: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ").strip()
        if not value and default is not None:
            return default
        return value

    def safe_call(label: str, fn, *fn_args, **fn_kwargs):
        try:
            print(f"\n== {label} ==")
            return fn(*fn_args, **fn_kwargs)
        except Exception as exc:
            print(f"ERROR during {label}: {exc}")
            # Keep trace only for debugging convenience.
            print("Traceback (debug):")
            traceback.print_exc()
            return None

    menu = """
COMP3334 Secure IM - Menu
1. Register
2. Login (password + OTP)
3. Logout (revoke token)
4. Add friend (send request)
5. Show friend requests (incoming + outgoing)
6. Respond to friend request (accept/decline)
7. Sync peer key + show fingerprint
8. Verify peer key (unblock sending)
9. Trust status for peer
10. Send message (E2EE) with TTL
11. Pull messages (decrypt + E2EE ACK)
12. Conversations (paged)
13. Exit
"""

    while True:
        print(menu)
        choice = ask("Choose an option", default="13")
        if choice == "1":
            username = ask("Username")
            password = ask("Password")
            safe_call("Register", im_client.register, username, password)
        elif choice == "2":
            username = ask("Username")
            password = ask("Password")
            otp = ask("OTP (6 digits)")
            safe_call("Login", im_client.login, username, password, otp)
        elif choice == "3":
            safe_call("Logout", im_client.logout)
        elif choice == "4":
            peer = ask("Receiver username (send friend request to)")
            safe_call("Add friend", im_client.add_friend, peer)
        elif choice == "5":
            limit = int(ask("Limit", default="20"))
            offset = int(ask("Offset", default="0"))
            safe_call("Friend requests", im_client.friend_requests, limit, offset)
        elif choice == "6":
            rid = int(ask("Request id"))
            action = ask("Action (accept/decline)").lower()
            safe_call("Respond friend request", im_client.respond_request, rid, action)
        elif choice == "7":
            peer = ask("Peer username to sync key with")
            safe_call("Sync peer key", im_client.sync_peer_key, peer)
        elif choice == "8":
            peer = ask("Peer username to verify")
            safe_call("Verify peer", im_client.verify_peer, peer)
        elif choice == "9":
            peer = ask("Peer username")
            safe_call("Trust status", im_client.trust_status, peer)
        elif choice == "10":
            peer = ask("Send to (peer username)")
            ttl = int(ask("TTL seconds", default="60"))
            text = ask("Message text")
            safe_call("Send message", im_client.send_message, peer, text, ttl)
        elif choice == "11":
            limit = int(ask("Limit", default="20"))
            offset = int(ask("Offset", default="0"))
            safe_call("Pull messages", im_client.pull, limit, offset)
        elif choice == "12":
            limit = int(ask("Limit", default="20"))
            offset = int(ask("Offset", default="0"))
            safe_call("Conversations", im_client.list_conversations_paged, limit, offset)
        elif choice == "13":
            print("Bye.")
            return
        else:
            print("Invalid option, try again.")


if __name__ == "__main__":
    main()

