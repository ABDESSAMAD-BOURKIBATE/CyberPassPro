import os
import tkinter as tk
from tkinter import messagebox, ttk
import secrets
import string
import qrcode
from PIL import Image, ImageTk
import arabic_reshaper
from bidi.algorithm import get_display
import json
from crypto_utils import CryptoUtils  # يفترض أنها مكتبة مخصصة

USER_FOLDER = "./data"

os.makedirs(USER_FOLDER, exist_ok=True)

def reshape_arabic(text):
    reshaped_text = arabic_reshaper.reshape(text)
    return get_display(reshaped_text)

class CyberPassProApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberPassPro - مدير كلمات المرور")
        self.geometry("800x700")
        self.configure(bg="#0A0A0A")
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Almarai", 11), padding=10, background="#333333", foreground="#FF00FF")
        self.style.configure("TEntry", padding=5, font=("Almarai", 11))
        self.style.configure("Signature.TLabel", font=("Almarai", 14, "bold"), foreground="#FF69B4", background="#1E1E1E", padding=8)
        self.style.configure("Timer.TLabel", font=("Almarai", 12, "bold"), foreground="#FF00FF", background="#0A0A0A")
        self.style.configure("QR.TLabel", font=("Almarai", 10), foreground="#00FFFF", background="#0A0A0A")

        # إعدادات الألوان والخطوط
        self.font_title = ("Almarai", 16, "bold")
        self.font_normal = ("Almarai", 11)
        self.bg_color = "#0A0A0A"
        self.fg_color = "#00FFFF"
        self.entry_bg = "#1E1E1E"
        self.button_bg = "#333333"
        self.button_fg = "#FF00FF"

        self.user_password = None
        self.user_folder = None
        self.fernet = None
        self.qr_img = None
        self.show_password = False
        self.timer_seconds = 180
        self.timer_running = False

        # تأثيرات hover
        self.style.map("TButton", background=[("active", "#FF00FF"), ("!active", "#333333")],
                       foreground=[("active", "#0A0A0A"), ("!active", "#FF00FF")])

        self.create_password_frame()

    def create_password_frame(self):
        self.clear_frame()

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=reshape_arabic("أدخل اسم المستخدم:"), font=self.font_title, foreground=self.fg_color, background=self.bg_color).grid(row=0, column=0, columnspan=2, pady=(20, 5))
        self.username_entry = ttk.Entry(frame, font=self.font_normal, justify='right')
        self.username_entry.grid(row=1, column=0, columnspan=2, pady=5, padx=50, sticky="ew")

        ttk.Label(frame, text=reshape_arabic("أدخل كلمة السر الرئيسية:"), font=self.font_title, foreground=self.fg_color, background=self.bg_color).grid(row=2, column=0, columnspan=2, pady=(20, 5))
        self.password_entry = ttk.Entry(frame, font=self.font_normal, show="*", justify='right')
        self.password_entry.grid(row=3, column=0, columnspan=2, pady=5, padx=50, sticky="ew")

        self.show_btn = ttk.Button(frame, text=reshape_arabic("إظهار"), command=self.toggle_password)
        self.show_btn.grid(row=4, column=0, columnspan=2, pady=5)

        btn_text = reshape_arabic("تأكيد")
        ttk.Button(frame, text=btn_text, command=self.confirm_password).grid(row=5, column=0, columnspan=2, pady=15)

        signature = reshape_arabic("عبد الصمد بوركيبات © 2025")
        ttk.Label(frame, text=signature, style="Signature.TLabel").grid(row=6, column=0, columnspan=2, pady=10)

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def toggle_password(self):
        self.show_password = not self.show_password
        self.password_entry.config(show="" if self.show_password else "*")
        self.show_btn.config(text=reshape_arabic("إخفاء" if self.show_password else "إظهار"))

    def confirm_password(self):
        username = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()

        if not username:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى إدخال اسم المستخدم."))
            return
        if not pwd:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى إدخال كلمة السر."))
            return
        if len(pwd) < 8:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("كلمة السر يجب أن تكون 8 أحرف على الأقل."))
            return

        try:
            self.user_folder = os.path.join(USER_FOLDER, username)
            os.makedirs(self.user_folder, exist_ok=True)
            crypto = CryptoUtils(self.user_folder)
            self.fernet = crypto.get_user_key(pwd)
            self.user_password = pwd
            self.create_main_frame(username)
            self.start_timer()
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في تهيئة التشفير: {str(e)}"))

    def start_timer(self):
        self.timer_seconds = 180
        self.timer_running = True
        self.update_timer()

    def update_timer(self):
        if self.timer_running and self.timer_seconds > 0:
            minutes = self.timer_seconds // 60
            seconds = self.timer_seconds % 60
            timer_text = reshape_arabic(f"الوقت المتبقي: {minutes:02d}:{seconds:02d}")
            self.timer_label.config(text=timer_text)
            self.timer_seconds -= 1
            self.after(1000, self.update_timer)
        elif self.timer_seconds <= 0:
            self.timer_running = False
            messagebox.showinfo(reshape_arabic("انتهى الوقت"), reshape_arabic("انتهت الجلسة. سيتم تسجيل الخروج."))
            self.logout()

    def create_main_frame(self, username):
        self.clear_frame()

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=reshape_arabic(f"مدير كلمات المرور - المستخدم: {username}"), font=self.font_title, foreground=self.fg_color, background=self.bg_color).grid(row=0, column=0, columnspan=2, pady=10)

        self.timer_label = ttk.Label(frame, text=reshape_arabic("الوقت المتبقي: 03:00"), style="Timer.TLabel")
        self.timer_label.grid(row=1, column=1, sticky="e", padx=20, pady=5)

        btn_logout_text = reshape_arabic("تسجيل خروج")
        ttk.Button(frame, text=btn_logout_text, command=self.logout, style="TButton").grid(row=1, column=0, sticky="w", padx=20, pady=5)

        ttk.Label(frame, text=reshape_arabic("اسم الكود:"), foreground=self.fg_color, background=self.bg_color, font=self.font_normal).grid(row=2, column=0, columnspan=2, pady=(10, 5))
        self.code_name_entry = ttk.Entry(frame, font=self.font_normal, justify='right')
        self.code_name_entry.grid(row=3, column=0, columnspan=2, pady=5, padx=50, sticky="ew")

        ttk.Button(frame, text=reshape_arabic("توليد كلمة سر"), command=self.generate_password).grid(row=4, column=0, columnspan=2, pady=5)

        ttk.Label(frame, text=reshape_arabic("كلمة السر:"), foreground=self.fg_color, background=self.bg_color, font=self.font_normal).grid(row=5, column=0, columnspan=2, pady=(10, 5))
        self.password_entry2 = ttk.Entry(frame, font=self.font_normal, justify='right')
        self.password_entry2.grid(row=6, column=0, columnspan=2, pady=5, padx=50, sticky="ew")

        frame_buttons = ttk.Frame(frame)
        frame_buttons.grid(row=7, column=0, columnspan=2, pady=10)
        ttk.Button(frame_buttons, text=reshape_arabic("حفظ الكود"), command=self.save_code).pack(side="left", padx=5)
        ttk.Button(frame_buttons, text=reshape_arabic("حذف كود"), command=self.delete_code).pack(side="left", padx=5)
        ttk.Button(frame_buttons, text=reshape_arabic("عرض الأكواد"), command=self.show_saved_codes).pack(side="left", padx=5)
        ttk.Button(frame_buttons, text=reshape_arabic("إنشاء QR Code"), command=lambda: self.generate_qr(self.password_entry2.get())).pack(side="left", padx=5)
        ttk.Button(frame_buttons, text=reshape_arabic("حفظ QR Code"), command=self.save_qr_code).pack(side="left", padx=5)
        ttk.Button(frame_buttons, text=reshape_arabic("إعادة ضبط"), command=self.clear_fields).pack(side="left", padx=5)

        self.text_area = tk.Text(frame, height=8, bg=self.entry_bg, fg=self.fg_color, font=("Almarai", 10))
        self.text_area.grid(row=8, column=0, columnspan=2, pady=10, padx=20, sticky="nsew")

        self.qr_frame = ttk.Frame(frame, style="TFrame")
        self.qr_frame.grid(row=9, column=0, columnspan=2, pady=10)
        self.qr_label = ttk.Label(self.qr_frame, background=self.bg_color, compound="top")
        self.qr_label.pack()
        self.qr_text = ttk.Label(self.qr_frame, text="", style="QR.TLabel", wraplength=300)
        self.qr_text.pack(pady=5)

        signature = reshape_arabic("عبد الصمد بوركيبات © 2025")
        ttk.Label(frame, text=signature, style="Signature.TLabel").grid(row=10, column=0, columnspan=2, pady=10)

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(8, weight=1)

    def clear_fields(self):
        self.code_name_entry.delete(0, tk.END)
        self.password_entry2.delete(0, tk.END)
        self.qr_label.configure(image='')
        self.qr_text.configure(text='')

    def logout(self):
        self.timer_running = False
        self.user_password = None
        self.user_folder = None
        self.fernet = None
        self.qr_img = None
        self.create_password_frame()

    def generate_password(self):
        length = 16
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        self.password_entry2.delete(0, tk.END)
        self.password_entry2.insert(0, pwd)
        self.generate_qr(pwd)

    def generate_qr(self, data):
        if not data:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى إدخال نص لإنشاء رمز QR."))
            return
        if len(data.encode('utf-8')) > 1200:  # حد أقل لضمان التوافق مع Google Lens
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("النص طويل جدًا لرمز QR. يرجى استخدام نص أقصر (أقل من 1200 بايت)."))
            return
        qr = qrcode.QRCode(
            version=5,  # إصدار متوسط لتحسين التوافق
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=6,  # حجم مناسب لـ 100x100
            border=2,  # حدود صغيرة
        )
        qr.add_data(data.encode('utf-8'))
        qr.make(fit=True)
        img = qr.make_image(fill_color="#00FFFF", back_color="#0A0A0A").convert('RGB')
        img = img.resize((100, 100), Image.Resampling.LANCZOS)
        self.qr_img = ImageTk.PhotoImage(img)
        self.qr_label.configure(image=self.qr_img)
        self.qr_image_pil = img
        self.qr_text.configure(text=reshape_arabic(f"رمز QR للنص: {data}"))
        messagebox.showinfo(reshape_arabic("نجاح"), reshape_arabic(f"تم إنشاء رمز QR للنص: {data}"))

    def save_qr_code(self):
        if not hasattr(self, 'qr_image_pil'):
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى إنشاء رمز QR أولاً."))
            return
        try:
            file_path = os.path.join(self.user_folder, f"qr_code_{self.code_name_entry.get().strip() or 'unnamed'}.png")
            self.qr_image_pil.save(file_path)
            messagebox.showinfo(reshape_arabic("نجاح"), reshape_arabic(f"تم حفظ رمز QR في: {file_path}"))
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في حفظ رمز QR: {str(e)}"))

    def save_code(self):
        name = self.code_name_entry.get().strip()
        pwd = self.password_entry2.get().strip()
        if not name or not pwd:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى تعبئة اسم الكود وكلمة السر."))
            return
        try:
            encrypted = self.fernet.encrypt(pwd.encode('utf-8')).hex()
            file_path = os.path.join(self.user_folder, "saved_codes.json")
            codes = {}
            if os.path.exists(file_path):
                with open(file_path, "r", encoding='utf-8') as f:
                    codes = json.load(f)
            codes[name] = encrypted
            with open(file_path, "w", encoding='utf-8') as f:
                json.dump(codes, f, ensure_ascii=False, indent=2)
            messagebox.showinfo(reshape_arabic("نجاح"), reshape_arabic(f"تم حفظ الكود '{name}' بنجاح."))
            self.clear_fields()
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في حفظ الكود: {str(e)}"))

    def delete_code(self):
        name = self.code_name_entry.get().strip()
        if not name:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("يرجى إدخال اسم الكود لحذفه."))
            return
        file_path = os.path.join(self.user_folder, "saved_codes.json")
        if not os.path.exists(file_path):
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic("لا توجد أكواد محفوظة."))
            return
        try:
            with open(file_path, "r", encoding='utf-8') as f:
                codes = json.load(f)
            if name not in codes:
                messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"الكود '{name}' غير موجود."))
                return
            del codes[name]
            with open(file_path, "w", encoding='utf-8') as f:
                json.dump(codes, f, ensure_ascii=False, indent=2)
            messagebox.showinfo(reshape_arabic("نجاح"), reshape_arabic(f"تم حذف الكود '{name}' بنجاح."))
            self.clear_fields()
            self.show_saved_codes()
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في حذف الكود: {str(e)}"))

    def show_saved_codes(self):
        self.text_area.delete(1.0, tk.END)
        file_path = os.path.join(self.user_folder, "saved_codes.json")
        if not os.path.exists(file_path):
            self.text_area.insert(tk.END, reshape_arabic("لا توجد أكواد محفوظة حتى الآن.\n"))
            return
        try:
            with open(file_path, "r", encoding='utf-8') as f:
                codes = json.load(f)
            for name, enc_hex in codes.items():
                try:
                    enc_bytes = bytes.fromhex(enc_hex)
                    decrypted = self.fernet.decrypt(enc_bytes).decode('utf-8')
                except Exception:
                    decrypted = reshape_arabic("[فشل فك التشفير]")
                display_name = reshape_arabic(name)
                self.text_area.insert(tk.END, f"{display_name} : {decrypted}\n")
        except Exception as e:
            messagebox.showerror(reshape_arabic("خطأ"), reshape_arabic(f"فشل في قراءة الأكواد: {str(e)}"))

    def clear_frame(self):
        for widget in self.winfo_children():
            widget.destroy()

    def on_closing(self):
        if messagebox.askokcancel(reshape_arabic("خروج"), reshape_arabic("هل أنت متأكد من الخروج؟")):
            self.destroy()

if __name__ == "__main__":
    app = CyberPassProApp()
    app.mainloop()
