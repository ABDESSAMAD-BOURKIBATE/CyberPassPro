

# 🛡️ CyberPassPro - مدير كلمات المرور الذكي

تطبيق مكتبي مبني بلغة Python بواجهة عربية 100% لحماية وتخزين كلمات المرور باستخدام التشفير القوي. مصمم خصيصًا ليكون بسيطًا، آمنًا، ومحليًا دون الاعتماد على خدمات سحابية.

> "لا تحفظ كلماتك السرية في المتصفح، بل احفظها مشفرة بين يديك."

---

## 🔧 ما هو CyberPassPro؟

هو مدير كلمات مرور مكتبي محلي يعمل عبر Python وواجهة رسومية (`Tkinter`) ويستخدم مكتبة `cryptography` لتشفير المعلومات وتخزينها بشكل آمن. يتم إنشاء مجلد خاص بكل مستخدم وتخزين الأكواد فيه مشفّرة.

---

## 🌟 المميزات

- 🔐 تشفير متقدم (AES + Fernet)
- 🇸🇦 دعم كامل للغة العربية (اليمين لليسار)
- 👤 إنشاء مجلد خاص لكل مستخدم
- 🎲 توليد كلمات مرور قوية تلقائيًا
- 💾 حفظ واسترجاع الأكواد المشفرة
- 🎨 واجهة رسومية أنيقة مع أزرار أيقونية
- ❌ تأكيد عند الخروج لحماية الجلسة

---

## 🚀 خطوات الاستخدام

### 1. التثبيت

تأكد من وجود Python 3.7 أو أحدث على جهازك، ثم ثبّت المكتبات المطلوبة:

```bash
pip install cryptography pillow arabic-reshaper python-bidi
````

### 2. تشغيل البرنامج

```bash
python CyberPassPro.py
```

---

## 📋 طريقة الاستخدام

1. قم بكتابة اسم المستخدم وكلمة السر الرئيسية (ستُستخدم للتشفير).
2. أنشئ أو ولّد كلمة مرور قوية.
3. اضغط على "حفظ الكود".
4. استخدم "عرض الأكواد" لعرض جميع كلمات المرور المخزنة.
5. اضغط "تسجيل خروج" لإغلاق الجلسة بأمان.

---

## 🧭 قوانين الاستخدام

* كلمة السر الرئيسية مطلوبة للوصول للبيانات.
* لا يمكن استرجاع الأكواد في حال فقدان كلمة السر.
* جميع الأكواد تُخزن مشفّرة في ملفات محلية.
* لا يتم تخزين أي بيانات في الإنترنت.
* كل مستخدم له مجلد خاص به داخل `./data/`.

---

## 📁 هيكل المشروع

```
CyberPassPro/
│
├── CyberPassPro.py          # ملف التشغيل الرئيسي
├── crypto_utils.py          # التشفير وفك التشفير
├── icons/                   # أيقونات الأزرار (confirm.png, logout.png...)
├── data/                    # مجلد المستخدمين (ينشأ تلقائيًا)
├── README.md                # هذا الملف
└── .gitignore               # ملفات يتم تجاهلها من git
```

---


---

## 🧠 المتطلبات التقنية

* Python 3.7 أو أحدث
* المكتبات:

  * `cryptography`
  * `Pillow`
  * `arabic-reshaper`
  * `python-bidi`

---

## 🧪 مثال على تشغيل مباشر (بافتراض أنك داخل مجلد المشروع)

```bash
https://github.com/ABDESSAMAD-BOURKIBATE/CyberPassPro.git
cd CyberPassPro
pip install -r requirements.txt
python CyberPassPro.py
```

> أو يمكنك إنشاء `requirements.txt` يحتوي على:

```
cryptography
pillow
arabic-reshaper
python-bidi
```

---

## 👨‍💻 المطوّر

**عبد الصمد بوركيبات**
باحث في الأمن السيبراني، والذكاء الاصطناعي .
📧 [bourkibate.abdessamad@gmail.com](mailto:bourkibate.abdessamad@gmail.com)
🔒 إصدار أولي: يوليو 2025

---

## 📜 الرخصة

مشروع مفتوح المصدر مرخّص تحت رخصة [MIT License](LICENSE)

---




