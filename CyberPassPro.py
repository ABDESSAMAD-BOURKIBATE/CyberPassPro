import os
import tkinter as tk
from tkinter import ttk, messagebox
from crypto_utils import CryptoUtils
import secrets
import string

# مكتبات دعم العربية
import arabic_reshaper
from bidi.algorithm import get_display

USER_FOLDER = "./data"  # نحتفظ بمجلد عام للمستخدمين (سنضيف مجلد لكل مستخدم)
os.makedirs(USER_FOLDER, exist_ok=True)

def reshape_arabic(text):
    reshaped_text = arabic_reshaper.reshape(text)    # إعادة تشكيل الحروف العربية
    bidi_text = get_display(reshaped_text)           # عكس النص للعرض من اليمين لليسار
    return bidi_text

class CyberPassProApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberPassPro - مدير كلمات المرور")
        self.geometry("600x450")
        self.configure(bg="#121212")

        self.font_title = ("Segoe UI", 14, "bold")
        self.font_normal = ("Segoe UI", 11)
        self.bg_color = "#121212"
        self.fg_color = "#EEEEEE"
        self.entry_bg = "#1E1E1E"
        self.button_bg = "#333333"
        self.button_fg = "#FFFFFF"

        self.user_password = None
        self.user_folder = None
        self.fernet = None

        self.create_password_frame()

    def create_password_frame(self):
        self.clear_frame()

        label_text = reshape_arabic("أدخل اسم المستخدم:")
        tk.Label(self, text=label_text, font=self.font_title, fg=self.fg_color, bg=self.bg_color).pack(pady=(20, 5))
        self.username_entry = tk.Entry(self, font=self.font_normal, bg=self.entry_bg, fg=self.fg_color, justify='right')
        self.username_entry.pack(pady=5)

        label_text2 = reshape_arabic("أدخل كلمة السر الرئيسية:")
        tk.Label(self, text=label_text2, font=self.font_title, fg=self.fg_color, bg=self.bg_color).pack(pady=(20, 5))
        self.password_entry = tk.Entry(self, show="*", font=self.font_normal, bg=self.entry_bg, fg=self.fg_color, justify='right')
        self.password_entry.pack(pady=5)

        btn_text = reshape_arabic("تأكيد")
        btn = tk.Button(self, text=btn_text, command=self.confirm_password, bg=self.button_bg, fg=self.button_fg, font=self.font_normal)
        btn.pack(pady=15)

    def confirm_password(self):
        username = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()

        if not username:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى إدخال اسم المستخدم."))
            return
        if not pwd:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى إدخال كلمة السر."))
            return

        try:
            # لكل مستخدم مجلد خاص
            self.user_folder = os.path.join(USER_FOLDER, username)
            os.makedirs(self.user_folder, exist_ok=True)
            crypto = CryptoUtils(self.user_folder)
            self.fernet = crypto.get_user_key(pwd)
            self.user_password = pwd
            self.create_main_frame(username)
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في تهيئة التشفير:\n{str(e)}"))

    def create_main_frame(self, username):
        self.clear_frame()

        header_text = reshape_arabic(f"مدير كلمات المرور - المستخدم: {username}")
        tk.Label(self, text=header_text, font=self.font_title, fg=self.fg_color, bg=self.bg_color).pack(pady=10)

        # زر تسجيل الخروج
        btn_logout_text = reshape_arabic("تسجيل خروج")
        tk.Button(self, text=btn_logout_text, command=self.logout, bg="#aa2222", fg=self.button_fg, font=self.font_normal).pack(anchor='ne', padx=20, pady=5)

        tk.Label(self, text=reshape_arabic("اسم الكود:"), fg=self.fg_color, bg=self.bg_color, font=self.font_normal).pack()
        self.code_name_entry = tk.Entry(self, font=self.font_normal, bg=self.entry_bg, fg=self.fg_color, justify='right')
        self.code_name_entry.pack(pady=5, fill="x", padx=50)

        btn_gen_text = reshape_arabic("توليد كلمة سر")
        tk.Button(self, text=btn_gen_text, command=self.generate_password, bg=self.button_bg, fg=self.button_fg, font=self.font_normal).pack(pady=5)

        tk.Label(self, text=reshape_arabic("كلمة السر:"), fg=self.fg_color, bg=self.bg_color, font=self.font_normal).pack()
        self.password_entry2 = tk.Entry(self, font=self.font_normal, bg=self.entry_bg, fg=self.fg_color, justify='right')
        self.password_entry2.pack(pady=5, fill="x", padx=50)

        btn_save_text = reshape_arabic("حفظ الكود")
        tk.Button(self, text=btn_save_text, command=self.save_code, bg=self.button_bg, fg=self.button_fg, font=self.font_normal).pack(pady=10)

        btn_show_text = reshape_arabic("عرض جميع الأكواد المحفوظة")
        tk.Button(self, text=btn_show_text, command=self.show_saved_codes, bg=self.button_bg, fg=self.button_fg, font=self.font_normal).pack(pady=5)

        self.text_area = tk.Text(self, height=8, bg=self.entry_bg, fg=self.fg_color, font=("Consolas", 10))
        self.text_area.pack(pady=10, padx=20, fill="both")

        signature = reshape_arabic("عبد الصمد بوركيبات © 2025")
        tk.Label(self, text=signature, fg="#888888", bg=self.bg_color, font=("Segoe UI", 9, "italic")).pack(side="bottom", pady=5)

    def logout(self):
        # إعادة تعيين المتغيرات ثم العودة لشاشة تسجيل الدخول
        self.user_password = None
        self.user_folder = None
        self.fernet = None
        self.create_password_frame()

    def generate_password(self):
        length = 16
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        self.password_entry2.delete(0, tk.END)
        self.password_entry2.insert(0, pwd)

    def save_code(self):
        name = self.code_name_entry.get().strip()
        pwd = self.password_entry2.get().strip()
        if not name or not pwd:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى تعبئة اسم الكود وكلمة السر."))
            return
        try:
            encrypted = self.fernet.encrypt(pwd.encode('utf-8'))
            file_path = os.path.join(self.user_folder, "saved_codes.dat")
            with open(file_path, "a", encoding='utf-8') as f:
                f.write(f"{name}::{encrypted.hex()}\n")
            messagebox.showinfo(reshape_arabic("نجاح"), reshape_arabic(f"تم حفظ الكود '{name}' بنجاح."))
            self.code_name_entry.delete(0, tk.END)
            self.password_entry2.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في حفظ الكود:\n{str(e)}"))

    def show_saved_codes(self):
        self.text_area.delete(1.0, tk.END)
        file_path = os.path.join(self.user_folder, "saved_codes.dat")
        if not os.path.exists(file_path):
            self.text_area.insert(tk.END, reshape_arabic("لا توجد أكواد محفوظة حتى الآن.\n"))
            return
        try:
            with open(file_path, "r", encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    name, enc_hex = line.split("::")
                    enc_bytes = bytes.fromhex(enc_hex)
                    try:
                        decrypted = self.fernet.decrypt(enc_bytes).decode('utf-8')
                    except Exception:
                        decrypted = reshape_arabic("[فشل فك التشفير]")
                    display_name = reshape_arabic(name)
                    self.text_area.insert(tk.END, f"{display_name} : {decrypted}\n")
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في قراءة الأكواد:\n{str(e)}"))

    def clear_frame(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    app = CyberPassProApp()
    app.mainloop()
