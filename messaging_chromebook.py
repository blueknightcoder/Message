#!/usr/bin/env python3
"""
Messaging App for Chromebook/Linux
A complete standalone messaging application.
Just run: python3 messaging_chromebook.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import threading
import json
from datetime import datetime

# Server configuration - Change this to your server's IP
SERVER_IP = "24.72.145.101"
SERVER_PORT = 5555


class MessagingApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("💬 Messaging")
        self.root.geometry("900x600")
        self.root.minsize(700, 500)
        
        # Configure colors
        self.colors = {
            "bg": "#1a1a2e",
            "sidebar": "#16213e",
            "chat_bg": "#0f0f23",
            "input_bg": "#1a1a2e",
            "accent": "#4361ee",
            "accent_hover": "#3a56d4",
            "text": "#ffffff",
            "text_muted": "#a0a0a0",
            "my_msg": "#4361ee",
            "other_msg": "#2d2d44",
            "online": "#4ade80",
            "border": "#2d2d44"
        }
        
        self.root.configure(bg=self.colors["bg"])
        
        # Connection state
        self.socket = None
        self.username = None
        self.connected = False
        self.chats = {}
        self.current_chat = None
        
        # Build UI
        self._create_styles()
        self._build_login_screen()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _create_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass
        
        style.configure("Sidebar.TFrame", background=self.colors["sidebar"])
        style.configure("Chat.TFrame", background=self.colors["chat_bg"])
        style.configure("Input.TFrame", background=self.colors["input_bg"])
    
    def _build_login_screen(self):
        """Show the login screen."""
        self.login_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo/Title
        title = tk.Label(self.login_frame, text="💬", font=("Sans", 48),
                        bg=self.colors["bg"], fg=self.colors["text"])
        title.pack(pady=(0, 10))
        
        subtitle = tk.Label(self.login_frame, text="Messaging",
                           font=("Sans", 24, "bold"),
                           bg=self.colors["bg"], fg=self.colors["text"])
        subtitle.pack(pady=(0, 30))
        
        # Server IP
        ip_label = tk.Label(self.login_frame, text="Server Address",
                           font=("Sans", 10),
                           bg=self.colors["bg"], fg=self.colors["text_muted"])
        ip_label.pack(anchor="w", padx=5)
        
        self.ip_entry = tk.Entry(self.login_frame, font=("Sans", 14),
                                bg=self.colors["input_bg"], fg=self.colors["text"],
                                insertbackground=self.colors["text"],
                                relief="flat", width=30)
        self.ip_entry.insert(0, SERVER_IP)
        self.ip_entry.pack(pady=(0, 15), ipady=8, padx=5)
        
        # Username
        user_label = tk.Label(self.login_frame, text="Username",
                             font=("Sans", 10),
                             bg=self.colors["bg"], fg=self.colors["text_muted"])
        user_label.pack(anchor="w", padx=5)
        
        self.username_entry = tk.Entry(self.login_frame, font=("Sans", 14),
                                       bg=self.colors["input_bg"], fg=self.colors["text"],
                                       insertbackground=self.colors["text"],
                                       relief="flat", width=30)
        self.username_entry.pack(pady=(0, 15), ipady=8, padx=5)
        
        # Password
        pass_label = tk.Label(self.login_frame, text="Password",
                             font=("Sans", 10),
                             bg=self.colors["bg"], fg=self.colors["text_muted"])
        pass_label.pack(anchor="w", padx=5)
        
        self.password_entry = tk.Entry(self.login_frame, font=("Sans", 14),
                                       bg=self.colors["input_bg"], fg=self.colors["text"],
                                       insertbackground=self.colors["text"],
                                       relief="flat", width=30, show="•")
        self.password_entry.pack(pady=(0, 20), ipady=8, padx=5)
        self.password_entry.bind("<Return>", lambda e: self._login())
        
        # Buttons frame
        btn_frame = tk.Frame(self.login_frame, bg=self.colors["bg"])
        btn_frame.pack(pady=10)
        
        # Login button
        self.login_btn = tk.Button(btn_frame, text="Login",
                                   font=("Sans", 12, "bold"),
                                   bg=self.colors["accent"], fg=self.colors["text"],
                                   relief="flat", cursor="hand2",
                                   command=self._login, width=12)
        self.login_btn.pack(side="left", padx=5, ipady=8)
        
        # Register button
        self.register_btn = tk.Button(btn_frame, text="Register",
                                      font=("Sans", 12, "bold"),
                                      bg=self.colors["border"], fg=self.colors["text"],
                                      relief="flat", cursor="hand2",
                                      command=self._register, width=12)
        self.register_btn.pack(side="left", padx=5, ipady=8)
        
        # Status
        self.login_status = tk.Label(self.login_frame, text="",
                                     font=("Sans", 10),
                                     bg=self.colors["bg"], fg=self.colors["text_muted"])
        self.login_status.pack(pady=10)
    
    def _build_main_screen(self):
        """Build the main chat interface."""
        self.login_frame.destroy()
        
        # Main container
        self.main_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.main_frame.pack(fill="both", expand=True)
        
        # === SIDEBAR ===
        self.sidebar = tk.Frame(self.main_frame, bg=self.colors["sidebar"], width=280)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        # User info header
        user_header = tk.Frame(self.sidebar, bg=self.colors["sidebar"])
        user_header.pack(fill="x", padx=15, pady=15)
        
        tk.Label(user_header, text=f"👤 {self.username}",
                font=("Sans", 14, "bold"),
                bg=self.colors["sidebar"], fg=self.colors["text"]).pack(side="left")
        
        online_dot = tk.Label(user_header, text="●",
                             font=("Sans", 10),
                             bg=self.colors["sidebar"], fg=self.colors["online"])
        online_dot.pack(side="left", padx=5)
        
        # New chat button
        new_chat_btn = tk.Button(self.sidebar, text="+ New Chat",
                                font=("Sans", 11),
                                bg=self.colors["accent"], fg=self.colors["text"],
                                relief="flat", cursor="hand2",
                                command=self._create_new_chat)
        new_chat_btn.pack(fill="x", padx=15, pady=(0, 10), ipady=8)
        
        # Online users button
        online_btn = tk.Button(self.sidebar, text="👥 See Online Users",
                              font=("Sans", 10),
                              bg=self.colors["border"], fg=self.colors["text"],
                              relief="flat", cursor="hand2",
                              command=self._show_online_users)
        online_btn.pack(fill="x", padx=15, pady=(0, 15), ipady=5)
        
        # Separator
        tk.Frame(self.sidebar, bg=self.colors["border"], height=1).pack(fill="x", padx=15)
        
        # Chats label
        tk.Label(self.sidebar, text="Your Chats",
                font=("Sans", 10),
                bg=self.colors["sidebar"], fg=self.colors["text_muted"]).pack(anchor="w", padx=15, pady=10)
        
        # Chat list
        self.chat_list_frame = tk.Frame(self.sidebar, bg=self.colors["sidebar"])
        self.chat_list_frame.pack(fill="both", expand=True, padx=5)
        
        self.chat_list_canvas = tk.Canvas(self.chat_list_frame, bg=self.colors["sidebar"],
                                          highlightthickness=0)
        self.chat_list_canvas.pack(side="left", fill="both", expand=True)
        
        self.chat_list_inner = tk.Frame(self.chat_list_canvas, bg=self.colors["sidebar"])
        self.chat_list_canvas.create_window((0, 0), window=self.chat_list_inner, anchor="nw")
        
        self.chat_list_inner.bind("<Configure>",
                                  lambda e: self.chat_list_canvas.configure(
                                      scrollregion=self.chat_list_canvas.bbox("all")))
        
        # === CHAT AREA ===
        self.chat_area = tk.Frame(self.main_frame, bg=self.colors["chat_bg"])
        self.chat_area.pack(side="right", fill="both", expand=True)
        
        # Chat header
        self.chat_header = tk.Frame(self.chat_area, bg=self.colors["sidebar"], height=60)
        self.chat_header.pack(fill="x")
        self.chat_header.pack_propagate(False)
        
        self.chat_title = tk.Label(self.chat_header, text="Select a chat",
                                   font=("Sans", 14, "bold"),
                                   bg=self.colors["sidebar"], fg=self.colors["text"])
        self.chat_title.pack(side="left", padx=20, pady=15)
        
        self.chat_actions = tk.Frame(self.chat_header, bg=self.colors["sidebar"])
        self.chat_actions.pack(side="right", padx=15)
        
        # Messages area
        self.messages_frame = tk.Frame(self.chat_area, bg=self.colors["chat_bg"])
        self.messages_frame.pack(fill="both", expand=True)
        
        self.messages_canvas = tk.Canvas(self.messages_frame, bg=self.colors["chat_bg"],
                                         highlightthickness=0)
        self.messages_scrollbar = ttk.Scrollbar(self.messages_frame, orient="vertical",
                                                command=self.messages_canvas.yview)
        self.messages_canvas.configure(yscrollcommand=self.messages_scrollbar.set)
        
        self.messages_scrollbar.pack(side="right", fill="y")
        self.messages_canvas.pack(side="left", fill="both", expand=True)
        
        self.messages_inner = tk.Frame(self.messages_canvas, bg=self.colors["chat_bg"])
        self.messages_window = self.messages_canvas.create_window((0, 0),
                                                                   window=self.messages_inner,
                                                                   anchor="nw")
        
        self.messages_inner.bind("<Configure>", self._on_messages_configure)
        self.messages_canvas.bind("<Configure>", self._on_canvas_configure)
        
        # Input area
        self.input_frame = tk.Frame(self.chat_area, bg=self.colors["input_bg"], height=70)
        self.input_frame.pack(fill="x", side="bottom")
        self.input_frame.pack_propagate(False)
        
        input_container = tk.Frame(self.input_frame, bg=self.colors["input_bg"])
        input_container.pack(fill="x", padx=15, pady=15)
        
        self.message_entry = tk.Entry(input_container, font=("Sans", 12),
                                      bg=self.colors["border"], fg=self.colors["text"],
                                      insertbackground=self.colors["text"],
                                      relief="flat")
        self.message_entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 10))
        self.message_entry.bind("<Return>", lambda e: self._send_message())
        
        send_btn = tk.Button(input_container, text="Send",
                            font=("Sans", 11, "bold"),
                            bg=self.colors["accent"], fg=self.colors["text"],
                            relief="flat", cursor="hand2",
                            command=self._send_message)
        send_btn.pack(side="right", ipadx=20, ipady=8)
        
        self._show_welcome()
    
    def _on_messages_configure(self, event):
        self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
        self.messages_canvas.yview_moveto(1.0)
    
    def _on_canvas_configure(self, event):
        self.messages_canvas.itemconfig(self.messages_window, width=event.width)
    
    def _show_welcome(self):
        """Show welcome message."""
        for widget in self.messages_inner.winfo_children():
            widget.destroy()
        
        welcome = tk.Frame(self.messages_inner, bg=self.colors["chat_bg"])
        welcome.pack(expand=True, pady=100)
        
        tk.Label(welcome, text="💬",
                font=("Sans", 48),
                bg=self.colors["chat_bg"], fg=self.colors["text_muted"]).pack()
        
        tk.Label(welcome, text="Welcome to Messaging!",
                font=("Sans", 16, "bold"),
                bg=self.colors["chat_bg"], fg=self.colors["text"]).pack(pady=10)
        
        tk.Label(welcome, text="Create a new chat or select an existing one.",
                font=("Sans", 11),
                bg=self.colors["chat_bg"], fg=self.colors["text_muted"]).pack()
    
    def _register(self):
        """Register a new account."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username:
            self.login_status.config(text="Please enter a username", fg="#ef4444")
            return
        
        if not password or len(password) < 4:
            self.login_status.config(text="Password must be at least 4 characters", fg="#ef4444")
            return
        
        self.login_status.config(text="Registering...", fg=self.colors["text_muted"])
        self.login_btn.config(state="disabled")
        self.register_btn.config(state="disabled")
        self.root.update()
        
        server_ip = self.ip_entry.get().strip()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server_ip, SERVER_PORT))
            sock.settimeout(None)
            
            message = json.dumps({"action": "register", "username": username, "password": password}) + "\n"
            sock.send(message.encode('utf-8'))
            
            buffer = ""
            while "\n" not in buffer:
                data = sock.recv(4096).decode('utf-8')
                if not data:
                    break
                buffer += data
            
            response = json.loads(buffer.split("\n")[0]) if buffer else {}
            
            if response.get("status") == "ok":
                self.login_status.config(text="Account created! You can now login.", fg="#4ade80")
            else:
                self.login_status.config(text=response.get("message", "Registration failed"), fg="#ef4444")
        except socket.timeout:
            self.login_status.config(text="Connection timed out", fg="#ef4444")
        except ConnectionRefusedError:
            self.login_status.config(text="Server not available", fg="#ef4444")
        except Exception as e:
            self.login_status.config(text=f"Error: {str(e)[:30]}", fg="#ef4444")
        finally:
            try:
                sock.close()
            except:
                pass
            self.login_btn.config(state="normal")
            self.register_btn.config(state="normal")
    
    def _login(self):
        """Login to the server."""
        server_ip = self.ip_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not server_ip:
            self.login_status.config(text="Please enter server address", fg="#ef4444")
            return
        
        if not username:
            self.login_status.config(text="Please enter your username", fg="#ef4444")
            return
        
        if not password:
            self.login_status.config(text="Please enter your password", fg="#ef4444")
            return
        
        self.login_status.config(text="Logging in...", fg=self.colors["text_muted"])
        self.login_btn.config(state="disabled")
        self.register_btn.config(state="disabled")
        self.root.update()
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((server_ip, SERVER_PORT))
            self.socket.settimeout(None)
            
            self._send_to_server({"action": "login", "username": username, "password": password})
            
            response = self._receive_one()
            if response.get("status") == "ok":
                self.username = username
                self.connected = True
                
                threading.Thread(target=self._receive_loop, daemon=True).start()
                self._build_main_screen()
            else:
                self.login_status.config(text=response.get("message", "Login failed"), fg="#ef4444")
                self.login_btn.config(state="normal")
                self.register_btn.config(state="normal")
                self.socket.close()
        
        except socket.timeout:
            self.login_status.config(text="Connection timed out", fg="#ef4444")
            self.login_btn.config(state="normal")
            self.register_btn.config(state="normal")
        except ConnectionRefusedError:
            self.login_status.config(text="Server not available", fg="#ef4444")
            self.login_btn.config(state="normal")
            self.register_btn.config(state="normal")
        except Exception as e:
            self.login_status.config(text=f"Error: {str(e)[:30]}", fg="#ef4444")
            self.login_btn.config(state="normal")
            self.register_btn.config(state="normal")
    
    def _send_to_server(self, data):
        """Send data to server."""
        try:
            message = json.dumps(data) + "\n"
            self.socket.send(message.encode('utf-8'))
        except:
            pass
    
    def _receive_one(self):
        """Receive a single message."""
        buffer = ""
        while "\n" not in buffer:
            data = self.socket.recv(4096).decode('utf-8')
            if not data:
                return {}
            buffer += data
        return json.loads(buffer.split("\n")[0])
    
    def _receive_loop(self):
        """Background thread to receive messages."""
        buffer = ""
        while self.connected:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                buffer += data
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        self.root.after(0, self._handle_message, json.loads(line))
            except:
                break
        
        self.connected = False
    
    def _handle_message(self, msg):
        """Handle incoming server messages."""
        action = msg.get("action")
        
        if action == "chat_list":
            for chat in msg.get("chats", []):
                self.chats[chat["chat_id"]] = {
                    "name": chat["name"],
                    "members": chat["members"],
                    "messages": []
                }
            self._refresh_chat_list()
        
        elif action == "chat_created":
            chat_id = msg["chat_id"]
            self.chats[chat_id] = {
                "name": msg["name"],
                "members": msg["members"],
                "messages": []
            }
            self._refresh_chat_list()
        
        elif action == "new_message":
            chat_id = msg["chat_id"]
            if chat_id in self.chats:
                self.chats[chat_id]["messages"].append({
                    "from": msg["from"],
                    "text": msg["text"],
                    "timestamp": msg["timestamp"]
                })
                if self.current_chat == chat_id:
                    self._display_messages()
        
        elif action == "message_history":
            chat_id = msg["chat_id"]
            if chat_id in self.chats:
                self.chats[chat_id]["messages"] = msg["messages"]
                if self.current_chat == chat_id:
                    self._display_messages()
        
        elif action == "user_list":
            self._show_user_list(msg["users"])
        
        elif action == "member_added":
            chat_id = msg["chat_id"]
            if chat_id in self.chats:
                self.chats[chat_id]["members"] = msg["members"]
        
        elif action == "member_left":
            chat_id = msg["chat_id"]
            if chat_id in self.chats:
                self.chats[chat_id]["members"] = msg["members"]
        
        elif action == "left_chat":
            chat_id = msg["chat_id"]
            if chat_id in self.chats:
                del self.chats[chat_id]
            if self.current_chat == chat_id:
                self.current_chat = None
                self._show_welcome()
            self._refresh_chat_list()
    
    def _refresh_chat_list(self):
        """Refresh the chat list in sidebar."""
        for widget in self.chat_list_inner.winfo_children():
            widget.destroy()
        
        for chat_id, chat in self.chats.items():
            btn = tk.Button(self.chat_list_inner, text=f"💬 {chat['name']}",
                           font=("Sans", 11),
                           bg=self.colors["sidebar"], fg=self.colors["text"],
                           relief="flat", anchor="w", cursor="hand2",
                           command=lambda cid=chat_id: self._select_chat(cid))
            btn.pack(fill="x", pady=2, padx=5, ipady=8)
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=self.colors["accent"]))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(bg=self.colors["sidebar"]))
    
    def _select_chat(self, chat_id):
        """Select a chat to view."""
        self.current_chat = chat_id
        chat = self.chats[chat_id]
        
        self.chat_title.config(text=f"💬 {chat['name']}")
        
        # Clear and add action buttons
        for widget in self.chat_actions.winfo_children():
            widget.destroy()
        
        add_btn = tk.Button(self.chat_actions, text="+ Add",
                           font=("Sans", 9),
                           bg=self.colors["border"], fg=self.colors["text"],
                           relief="flat", cursor="hand2",
                           command=lambda: self._add_member_dialog(chat_id))
        add_btn.pack(side="left", padx=2)
        
        leave_btn = tk.Button(self.chat_actions, text="Leave",
                             font=("Sans", 9),
                             bg="#ef4444", fg=self.colors["text"],
                             relief="flat", cursor="hand2",
                             command=lambda: self._leave_chat(chat_id))
        leave_btn.pack(side="left", padx=2)
        
        # Request message history
        self._send_to_server({"action": "get_messages", "chat_id": chat_id})
        self._display_messages()
    
    def _display_messages(self):
        """Display messages for current chat."""
        for widget in self.messages_inner.winfo_children():
            widget.destroy()
        
        if self.current_chat not in self.chats:
            return
        
        chat = self.chats[self.current_chat]
        
        for msg in chat["messages"]:
            is_mine = msg["from"] == self.username
            
            msg_frame = tk.Frame(self.messages_inner, bg=self.colors["chat_bg"])
            msg_frame.pack(fill="x", pady=5, padx=15)
            
            bubble = tk.Frame(msg_frame, bg=self.colors["my_msg"] if is_mine else self.colors["other_msg"])
            bubble.pack(side="right" if is_mine else "left", padx=5)
            
            if not is_mine:
                tk.Label(bubble, text=msg["from"],
                        font=("Sans", 9, "bold"),
                        bg=bubble["bg"], fg=self.colors["accent"]).pack(anchor="w", padx=10, pady=(8, 0))
            
            tk.Label(bubble, text=msg["text"],
                    font=("Sans", 11),
                    bg=bubble["bg"], fg=self.colors["text"],
                    wraplength=400, justify="left").pack(anchor="w", padx=10, pady=(4, 4))
            
            tk.Label(bubble, text=msg["timestamp"].split(" ")[1][:5] if " " in msg["timestamp"] else "",
                    font=("Sans", 8),
                    bg=bubble["bg"], fg=self.colors["text_muted"]).pack(anchor="e", padx=10, pady=(0, 8))
    
    def _send_message(self):
        """Send a message to the current chat."""
        if not self.current_chat:
            return
        
        text = self.message_entry.get().strip()
        if not text:
            return
        
        self._send_to_server({
            "action": "send_message",
            "chat_id": self.current_chat,
            "text": text
        })
        
        self.message_entry.delete(0, tk.END)
    
    def _create_new_chat(self):
        """Create a new chat."""
        name = simpledialog.askstring("New Chat", "Enter chat name:",
                                      parent=self.root)
        if name:
            self._send_to_server({
                "action": "create_chat",
                "name": name,
                "members": [self.username]
            })
    
    def _show_online_users(self):
        """Request online users list."""
        self._send_to_server({"action": "list_users"})
    
    def _show_user_list(self, users):
        """Display online users."""
        user_str = "\n".join(f"• {u}" for u in users)
        messagebox.showinfo("Online Users", f"Currently online:\n\n{user_str}")
    
    def _add_member_dialog(self, chat_id):
        """Show dialog to add member."""
        username = simpledialog.askstring("Add Member", "Enter username to add:",
                                          parent=self.root)
        if username:
            self._send_to_server({
                "action": "add_member",
                "chat_id": chat_id,
                "username": username
            })
    
    def _leave_chat(self, chat_id):
        """Leave a chat."""
        if messagebox.askyesno("Leave Chat", "Are you sure you want to leave this chat?"):
            self._send_to_server({
                "action": "leave_chat",
                "chat_id": chat_id
            })
    
    def _on_close(self):
        """Handle window close."""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.root.destroy()
    
    def run(self):
        """Start the application."""
        self.root.mainloop()


if __name__ == "__main__":
    app = MessagingApp()
    app.run()
