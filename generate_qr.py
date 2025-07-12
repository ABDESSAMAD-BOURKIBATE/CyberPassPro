from PIL import Image, ImageDraw, ImageFont
import qrcode
import arabic_reshaper
from bidi.algorithm import get_display

# --- إعداد النص ---
arabic_text = "مدير كلمات السر - عبد الصمد بوركيبات"
reshaped_text = arabic_reshaper.reshape(arabic_text)
bidi_text = get_display(reshaped_text)

# --- توليد رمز QR ---
data_link = "https://github.com/bourkibate/CyberPassPro"
qr = qrcode.QRCode(box_size=10, border=4)
qr.add_data(data_link)
qr.make(fit=True)
qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

# --- تحميل الخط العربي ---
try:
    font = ImageFont.truetype("arial.ttf", 28)  # أو ضع مسار خط عربي لديك
except:
    font = ImageFont.load_default()

# --- تجهيز الصورة النهائية ---
qr_width, qr_height = qr_img.size
text_height = 50
padding = 20
total_height = qr_height + text_height + padding

final_img = Image.new("RGB", (qr_width, total_height), "white")
final_img.paste(qr_img, (0, 0))

# --- كتابة النص تحت الرمز ---
draw = ImageDraw.Draw(final_img)
text_width, _ = draw.textsize(bidi_text, font=font)
x = (qr_width - text_width) // 2
y = qr_height + 10
draw.text((x, y), bidi_text, font=font, fill="black")

# --- عرض أو حفظ ---
final_img.show()
final_img.save("CyberQR.png")
