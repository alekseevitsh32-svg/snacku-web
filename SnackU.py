# -*- coding: utf-8 -*-
"""
SnackU — единый файл.
Первый запуск — установка + ярлык на рабочем столе.
Дальше — приложение.
"""
import os
import sys
import stat
import subprocess

sys.dont_write_bytecode = True

BASE = r'C:\SnackU'
INSTALL_FLAG = os.path.join(BASE, 'files32', 'main.py')


INIT_FILE = '# -*- coding: utf-8 -*-\n'

# ==================== main.py ====================
MAIN_FILE = r'''# -*- coding: utf-8 -*-
"""SnackU — главный запуск."""
import os
import sys
import json
import tkinter as tk

BASE = r'C:\SnackU'
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from files32.security import (
    get_pc_fingerprint, compute_hash,
    STATE_FILE, SX_FILE, integrity_ok,
)


def show_fraud_error(title='Верните Аккаунт Владельцу!',
                     text='Аккаунт SnackU привязан к этому компьютеру.\n'
                          'Обнаружена попытка входа с другого устройства.'):
    r = tk.Tk()
    r.title('SnackU — Ошибка')
    r.geometry('460x300')
    r.configure(bg='#0f172a')
    r.resizable(False, False)
    r.update_idletasks()
    w, h = 460, 300
    x = (r.winfo_screenwidth() - w) // 2
    y = (r.winfo_screenheight() - h) // 2
    r.geometry(f'{w}x{h}+{x}+{y}')

    tk.Label(r, text='!', bg='#0f172a', fg='#ef4444',
             font=('Segoe UI', 48, 'bold')).pack(pady=(25, 0))
    tk.Label(r, text=title, bg='#0f172a', fg='#ef4444',
             font=('Segoe UI', 16, 'bold')).pack(pady=5)
    tk.Label(r, text=text, bg='#0f172a', fg='#94a3b8',
             font=('Segoe UI', 10), justify='center').pack(pady=10)
    tk.Button(r, text='Закрыть', command=r.destroy,
              bg='#ef4444', fg='white', bd=0,
              font=('Segoe UI', 11, 'bold'),
              cursor='hand2', padx=30, pady=8).pack(pady=15)
    r.mainloop()
    os._exit(1)


def _read(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def _restore(state):
    try:
        from files32.security import make_writable, make_readonly, SX_DIR
        os.makedirs(SX_DIR, exist_ok=True)
        if os.path.exists(SX_FILE):
            make_writable(SX_FILE)
        with open(SX_FILE, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=4)
        make_readonly(SX_FILE)
    except Exception:
        pass


def load_user():
    if not integrity_ok():
        show_fraud_error(title='Файлы SnackU изменены!',
                         text='Файлы мессенджера были изменены извне.\n'
                              'Запуск заблокирован.')

    st = _read(STATE_FILE)
    if st:
        h1 = st.get('fingerprint_hash', '')
        h2 = compute_hash(get_pc_fingerprint())
        if not h1 or h1 != h2:
            show_fraud_error()
        if not os.path.exists(SX_FILE):
            _restore(st)
        return (st.get('phone', ''), st.get('name', ''), st.get('surname', ''))

    if os.path.exists(SX_FILE):
        d = _read(SX_FILE)
        if d:
            h1 = d.get('fingerprint_hash', '')
            h2 = compute_hash(get_pc_fingerprint())
            if not h1 or h1 != h2:
                show_fraud_error()
            try:
                from files32.security import save_state
                save_state(d)
            except Exception:
                pass
            return (d.get('phone', ''), d.get('name', ''), d.get('surname', ''))
    return None


def main():
    user = load_user()
    if user is None:
        from GUIREG.register import run_register
        user = run_register()
        if not user:
            print('Регистрация отменена.')
            return
    phone, name, surname = user
    print(f'Пользователь: {name} {surname}, тел. {phone}')
    from Messeng.MessengGUI.chat import run_chat
    run_chat(phone, name, surname)


if __name__ == '__main__':
    main()
'''

# ==================== security.py ====================
SECURITY_FILE = r'''# -*- coding: utf-8 -*-
"""SnackU — защита."""
import os, stat, platform, socket, uuid, hashlib, subprocess, json

_S1='Sn'; _S2='ack'; _S3='U_'; _S4='2k24_'; _S5='v1_'
SALT = _S1+_S2+_S3+_S4+_S5+'a8f3e2c1b9d7e6f4'

BASE      = r'C:\SnackU'
SX_DIR    = os.path.join(BASE, 'SX')
SX_FILE   = os.path.join(SX_DIR, 'user.json')
STATE_DIR = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'SnackU')
STATE_FILE = os.path.join(STATE_DIR, '.state')
INTEGRITY_FILE = os.path.join(STATE_DIR, '.integrity')


def protected_files():
    return [
        os.path.join(BASE, 'files32', 'main.py'),
        os.path.join(BASE, 'files32', 'security.py'),
        os.path.join(BASE, 'files32', 'network.py'),
        os.path.join(BASE, 'GUIREG', 'register.py'),
        os.path.join(BASE, 'Messeng', 'MessengGUI', 'chat.py'),
        SX_FILE, STATE_FILE,
    ]


def get_pc_fingerprint():
    info = {}
    info['username'] = os.environ.get('USERNAME', '')
    try: info['computer'] = socket.gethostname()
    except Exception: info['computer'] = ''
    try: info['mac'] = hex(uuid.getnode())
    except Exception: info['mac'] = ''
    try:
        info['platform'] = platform.system()
        info['release'] = platform.release()
        info['machine'] = platform.machine()
    except Exception: pass
    try:
        import ctypes
        info['lang'] = ctypes.windll.kernel32.GetUserDefaultUILanguage()
    except Exception: info['lang'] = 0
    return info


def compute_hash(fp):
    parts = [f'{k}={fp.get(k,"")}' for k in sorted(fp.keys())]
    return hashlib.sha256((SALT + '|'.join(parts)).encode('utf-8')).hexdigest()


def file_sha256(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ''


def make_readonly(path):
    if not os.path.exists(path): return
    try: os.chmod(path, stat.S_IREAD)
    except Exception: pass
    try:
        subprocess.run(['attrib','+R','+H','+S',path],
                       shell=True, capture_output=True, check=False)
    except Exception: pass
    try:
        user = os.environ.get('USERNAME','')
        if user:
            subprocess.run(['icacls', path, '/deny', f'{user}:(W,M,D)'],
                           shell=True, capture_output=True, check=False)
    except Exception: pass


def make_writable(path):
    if not os.path.exists(path): return
    try:
        user = os.environ.get('USERNAME','')
        if user:
            subprocess.run(['icacls', path, '/remove:d', user],
                           shell=True, capture_output=True, check=False)
    except Exception: pass
    try: os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except Exception: pass
    try:
        subprocess.run(['attrib','-R','-H','-S',path],
                       shell=True, capture_output=True, check=False)
    except Exception: pass


def protect_all():
    for p in protected_files():
        if os.path.exists(p):
            make_readonly(p)


def save_state(data):
    os.makedirs(STATE_DIR, exist_ok=True)
    if os.path.exists(STATE_FILE):
        make_writable(STATE_FILE)
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    make_readonly(STATE_FILE)


def save_integrity():
    os.makedirs(STATE_DIR, exist_ok=True)
    h = {}
    for p in protected_files():
        if p.endswith('.py') and os.path.exists(p):
            h[p] = file_sha256(p)
    if os.path.exists(INTEGRITY_FILE):
        make_writable(INTEGRITY_FILE)
    with open(INTEGRITY_FILE, 'w', encoding='utf-8') as f:
        json.dump(h, f, ensure_ascii=False, indent=4)
    make_readonly(INTEGRITY_FILE)


def integrity_ok():
    if not os.path.exists(INTEGRITY_FILE):
        return True
    try:
        with open(INTEGRITY_FILE, 'r', encoding='utf-8') as f:
            saved = json.load(f)
    except Exception:
        return True
    for path, expected in saved.items():
        actual = file_sha256(path)
        if not actual or actual != expected:
            return False
    return True
'''

# ==================== network.py ====================
NETWORK_FILE = r'''# -*- coding: utf-8 -*-
"""SnackU — сетевой клиент (Vercel API)."""
import json
import urllib.request
import urllib.error
import socket

# ⚠️ ЗАМЕНИ на свой домен Vercel
API_URL = 'https://snacku-web.vercel.app/api'

REQUEST_TIMEOUT = 12


def _post(payload):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(API_URL, data=body, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'SnackU-Client')

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return resp.status, data
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode('utf-8'))
        except Exception:
            data = {'status': 'error', 'message': f'HTTP {e.code}'}
        return e.code, data
    except socket.timeout:
        return 0, {'status': 'error',
                   'message': 'Сервер Перегружен Попробуйте ещё Раз'}
    except Exception as e:
        return 0, {'status': 'error', 'message': f'Ошибка сети: {e}'}


def server_ping(host=None, port=None, timeout=3):
    return True


def register_on_server(phone, name, surname):
    status, data = _post({
        'action': 'register',
        'phone': phone,
        'name': name,
        'surname': surname,
    })
    if status == 200 and data.get('status') == 'ok':
        return True, 'ok'
    msg = data.get('message') or data.get('detail') or f'HTTP {status}'
    return False, msg


def lookup_on_server(phone):
    status, data = _post({'action': 'lookup', 'phone': phone})
    if status == 200 and data.get('status') == 'ok':
        if data.get('found'):
            return data.get('user'), None
        return None, None
    msg = data.get('message') or data.get('detail') or f'HTTP {status}'
    return None, msg


def send_heartbeat(phone):
    status, data = _post({'action': 'heartbeat', 'phone': phone})
    return status == 200 and data.get('status') == 'ok'


def send_message(from_phone, to_phone, text):
    status, data = _post({
        'action': 'send_message',
        'from': from_phone,
        'to': to_phone,
        'text': text,
    })
    if status == 200 and data.get('status') == 'ok':
        return True, data.get('message')
    msg = data.get('message') or data.get('detail') or f'HTTP {status}'
    return False, msg


def get_messages(from_phone, to_phone, since=0):
    status, data = _post({
        'action': 'get_messages',
        'from': from_phone,
        'to': to_phone,
        'since': since,
    })
    if status == 200 and data.get('status') == 'ok':
        return data.get('messages', [])
    return []
'''

# ==================== register.py ====================
REGISTER_FILE = r'''# -*- coding: utf-8 -*-
import tkinter as tk
import re, os, sys, json

if r'C:\SnackU' not in sys.path:
    sys.path.insert(0, r'C:\SnackU')

BG='#0f172a'; CARD='#1e293b'; FIELD_BG='#334155'; FIELD_BORDER='#475569'
TEXT='#f1f5f9'; MUTED='#94a3b8'; ACCENT='#3b82f6'; ACCENT_HOVER='#2563eb'
DISABLED='#475569'; ERROR='#ef4444'

F_TITLE=('Segoe UI',18,'bold'); F_SUB=('Segoe UI',10); F_LABEL=('Segoe UI',10)
F_INPUT=('Segoe UI',12); F_BTN=('Segoe UI',12,'bold'); F_ERR=('Segoe UI',9)
F_LINK=('Segoe UI',10)

SX_DIR=r'C:\SnackU\SX'
SX_FILE=os.path.join(SX_DIR,'user.json')
ICON_FILE=r'C:\SnackU\files32\icon.ico'

NAME_RE = re.compile(r"^[А-Яа-яЁёA-Za-z]+(?:[-'\s][А-Яа-яЁёA-Za-z]+)*$")


def normalize_phone(phone):
    return re.sub(r'[\s\-\(\)]', '', phone or '')


def is_valid_phone(phone):
    cleaned = normalize_phone(phone)
    if not re.fullmatch(r'\+7\d{10}', cleaned):
        return False, '', 'Невалидный номер'
    digits = cleaned[2:]
    if len(set(digits)) == 1:
        return False, '', 'Невалидный номер: все цифры одинаковые'
    if digits[0] in ('0', '7'):
        return False, '', 'Невалидный номер: неверный код оператора'
    return True, cleaned, ''


def save_user(phone, name, surname):
    phone = normalize_phone(phone)

    from files32.security import (get_pc_fingerprint, compute_hash,
        make_readonly, make_writable, save_state, save_integrity, protect_all)
    from files32.network import register_on_server

    os.makedirs(SX_DIR, exist_ok=True)
    if os.path.exists(SX_FILE):
        make_writable(SX_FILE)

    fp = get_pc_fingerprint()
    data = {'phone': phone, 'name': name, 'surname': surname,
            'fingerprint': fp, 'fingerprint_hash': compute_hash(fp)}

    with open(SX_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    make_readonly(SX_FILE)

    ok, msg = register_on_server(phone, name, surname)
    if ok:
        print(f'[SX] {phone} загружен на сервер')
    else:
        print(f'[SX] ошибка сервера: {msg}')

    save_state(data); save_integrity(); protect_all()
    return ok, msg


class RoundedEntry(tk.Frame):
    def __init__(self, master, placeholder='', show=None,
                 numeric_only=False, name_only=False, **kw):
        super().__init__(master, bg=CARD)
        self.canvas = tk.Canvas(self, bg=CARD, highlightthickness=0, height=44, bd=0)
        self.canvas.pack(fill='x')
        self.entry = tk.Entry(self.canvas, bd=0, relief='flat',
                              bg=FIELD_BG, fg=TEXT, insertbackground=TEXT,
                              font=F_INPUT, show=show)
        self.entry.place(x=14, y=11, width=280, height=22)
        self.placeholder = placeholder
        self.placeholder_active = False
        self._change_callback = None
        self.numeric_only = numeric_only
        self.name_only = name_only
        if numeric_only or name_only:
            vcmd = (self.register(self._validate), '%P')
            self.entry.config(validate='key', validatecommand=vcmd)
        self._draw(FIELD_BORDER)
        self.canvas.bind('<Configure>', lambda e: self._draw(FIELD_BORDER))
        self.entry.bind('<FocusIn>', self._on_focus_in)
        self.entry.bind('<FocusOut>', self._on_focus_out)
        self.entry.bind('<KeyRelease>', self._notify_change)
        if placeholder:
            self._show_placeholder()

    def _validate(self, t):
        if self.numeric_only:
            return all(c in '0123456789+ ()-' for c in t)
        if self.name_only:
            if t == '': return True
            return all(c.isalpha() or c in "-' " for c in t)
        return True

    def _notify_change(self, event=None):
        if self._change_callback: self._change_callback()

    def set_on_change(self, cb): self._change_callback = cb

    def _draw(self, border):
        self.canvas.delete('all')
        w = self.canvas.winfo_width() or 320
        h, r = 44, 10
        self._rr(4,4,w-4,h-4,r,FIELD_BG,'')
        self._rr(4,4,w-4,h-4,r,'',border,1)
        try: self.entry.place_configure(width=max(10, w-28))
        except tk.TclError: pass

    def _rr(self, x1,y1,x2,y2,r,fill,outline,width=1):
        c = self.canvas
        c.create_arc(x1,y1,x1+2*r,y1+2*r,start=90,extent=90,fill=fill,outline=outline,width=width)
        c.create_arc(x2-2*r,y1,x2,y1+2*r,start=0,extent=90,fill=fill,outline=outline,width=width)
        c.create_arc(x1,y2-2*r,x1+2*r,y2,start=180,extent=90,fill=fill,outline=outline,width=width)
        c.create_arc(x2-2*r,y2-2*r,x2,y2,start=270,extent=90,fill=fill,outline=outline,width=width)
        c.create_rectangle(x1+r,y1,x2-r,y2,fill=fill,outline=outline,width=width)
        c.create_rectangle(x1,y1+r,x2,y2-r,fill=fill,outline=outline,width=width)

    def _on_focus_in(self, e):
        self._draw(ACCENT)
        if self.placeholder_active:
            self.entry.delete(0,'end')
            self.entry.config(fg=TEXT)
            self.placeholder_active = False
            self._notify_change()

    def _on_focus_out(self, e):
        self._draw(FIELD_BORDER)
        if not self.entry.get():
            self._show_placeholder()
            self._notify_change()

    def _show_placeholder(self):
        self.entry.insert(0, self.placeholder)
        self.entry.config(fg=MUTED)
        self.placeholder_active = True

    def get(self):
        return '' if self.placeholder_active else self.entry.get()

    def focus(self): self.entry.focus()


class RoundedButton(tk.Canvas):
    def __init__(self, master, text, command, width=320, height=46,
                 bg=ACCENT, hover=ACCENT_HOVER, disabled_bg=DISABLED, **kw):
        super().__init__(master, width=width, height=height, bg=CARD,
                         highlightthickness=0, bd=0)
        self.command=command; self.text=text; self.bg_color=bg
        self.hover_color=hover; self.disabled_bg=disabled_bg
        self.enabled=True; self._w=width; self._h=height
        self._draw(bg)
        self.bind('<Enter>', self._en)
        self.bind('<Leave>', self._lv)
        self.bind('<Button-1>', self._cl)

    def _draw(self, color):
        self.delete('all')
        w,h = self._w, self._h
        r = h//2
        c = self
        c.create_arc(0,0,2*r,h,start=90,extent=90,fill=color,outline=color)
        c.create_arc(w-2*r,0,w,h,start=0,extent=90,fill=color,outline=color)
        c.create_arc(0,h-2*r,2*r,h,start=180,extent=90,fill=color,outline=color)
        c.create_arc(w-2*r,h-2*r,w,h,start=270,extent=90,fill=color,outline=color)
        c.create_rectangle(r,0,w-r,h,fill=color,outline=color)
        c.create_rectangle(0,r,w,h-r,fill=color,outline=color)
        c.create_text(w//2,h//2,text=self.text,fill='white',font=F_BTN)

    def _en(self,e):
        if self.enabled: self._draw(self.hover_color)
    def _lv(self,e):
        if self.enabled: self._draw(self.bg_color)
    def _cl(self,e):
        if self.enabled and self.command: self.command()
    def set_enabled(self, s):
        self.enabled = s
        self._draw(self.bg_color if s else self.disabled_bg)
    def set_text(self, text):
        self.text = text
        self._draw(self.bg_color if self.enabled else self.disabled_bg)


def run_register():
    result = {'data': None}
    root = tk.Tk()
    root.title('SnackU — Регистрация')
    root.geometry('420x560')
    root.configure(bg=BG)
    root.resizable(False, False)
    try:
        if os.path.exists(ICON_FILE): root.iconbitmap(ICON_FILE)
    except Exception: pass
    root.update_idletasks()
    w,h=420,560
    x=(root.winfo_screenwidth()-w)//2
    y=(root.winfo_screenheight()-h)//2
    root.geometry(f'{w}x{h}+{x}+{y}')

    def on_close():
        result['data']=None; root.destroy()
    root.protocol('WM_DELETE_WINDOW', on_close)

    card = tk.Frame(root, bg=CARD)
    card.place(relx=0.5, rely=0.5, anchor='center', width=360, height=500)

    step1 = tk.Frame(card, bg=CARD)
    tk.Label(step1, text='SnackU 👋', bg=CARD, fg=TEXT, font=F_TITLE).pack(anchor='w', pady=(0,4))
    tk.Label(step1, text='Введите номер телефона', bg=CARD, fg=MUTED, font=F_SUB).pack(anchor='w', pady=(0,25))
    tk.Label(step1, text='Номер телефона', bg=CARD, fg=MUTED, font=F_LABEL).pack(anchor='w', pady=(0,6))

    phone_field = RoundedEntry(step1, placeholder='+7 999 123-45-67', numeric_only=True)
    phone_field.pack(fill='x')

    phone_error = tk.Label(step1, text='', bg=CARD, fg=ERROR, font=F_ERR, anchor='w')
    phone_error.pack(fill='x', pady=(6,14))

    next_btn = RoundedButton(step1, 'Далее', command=lambda: go_to_step2())
    next_btn.pack(pady=(10,0))
    next_btn.set_enabled(False)

    _after = {'id': None}

    def _check():
        v = phone_field.get().strip()
        if v == '':
            phone_error.config(text=''); next_btn.set_enabled(False); return
        ok, cleaned, err = is_valid_phone(v)
        if ok:
            phone_error.config(text=''); next_btn.set_enabled(True)
        else:
            phone_error.config(text=err); next_btn.set_enabled(False)

    def check():
        if _after['id']:
            try: root.after_cancel(_after['id'])
            except Exception: pass
        _after['id'] = root.after(80, _check)

    phone_field.set_on_change(check)

    step2 = tk.Frame(card, bg=CARD)
    tk.Label(step2, text='Как вас зовут?', bg=CARD, fg=TEXT, font=F_TITLE).pack(anchor='w', pady=(0,4))
    tk.Label(step2, text='Заполните имя и фамилию', bg=CARD, fg=MUTED, font=F_SUB).pack(anchor='w', pady=(0,25))
    tk.Label(step2, text='Имя', bg=CARD, fg=MUTED, font=F_LABEL).pack(anchor='w', pady=(0,6))
    name_field = RoundedEntry(step2, placeholder='Иван', name_only=True)
    name_field.pack(fill='x')
    tk.Label(step2, text='Фамилия', bg=CARD, fg=MUTED, font=F_LABEL).pack(anchor='w', pady=(14,6))
    surname_field = RoundedEntry(step2, placeholder='Иванов', name_only=True)
    surname_field.pack(fill='x')
    name_error = tk.Label(step2, text='', bg=CARD, fg=ERROR, font=F_ERR, anchor='w')
    name_error.pack(fill='x', pady=(6,14))

    def on_finish():
        n = name_field.get().strip()
        s = surname_field.get().strip()
        if not n or not s:
            name_error.config(text='Заполните имя и фамилию'); return
        if not NAME_RE.match(n):
            name_error.config(text='Имя — только буквы'); return
        if not NAME_RE.match(s):
            name_error.config(text='Фамилия — только буквы'); return

        raw_phone = phone_field.get().strip()
        ok, phone, err = is_valid_phone(raw_phone)
        if not ok:
            name_error.config(text=err); return

        try:
            online, msg = save_user(phone, n, s)
        except Exception as e:
            name_error.config(text=f'Ошибка: {e}'); return

        for w in step2.winfo_children(): w.destroy()

        tk.Label(step2, text='✅ Готово!', bg=CARD, fg='#22c55e', font=F_TITLE).pack(anchor='w', pady=(0,8))
        tk.Label(step2, text='Ты в базе SnackU!', bg=CARD, fg=TEXT,
                 font=('Segoe UI',14,'bold')).pack(anchor='w', pady=(0,6))
        tk.Label(step2, text=f'Твой номер:\n{phone}', bg=CARD, fg=TEXT,
                 font=('Segoe UI',13), justify='left').pack(anchor='w', pady=(0,12))

        if online:
            tk.Label(step2, text='Теперь любой, кто введёт этот номер\nв SnackU, сможет тебя найти.',
                     bg=CARD, fg=MUTED, font=F_SUB, justify='left',
                     wraplength=300).pack(anchor='w', pady=(0,20))
        else:
            tk.Label(step2, text=f'⚠ {msg}', bg=CARD, fg=ERROR, font=F_SUB,
                     justify='left', wraplength=300).pack(anchor='w', pady=(0,20))

        def fin():
            result['data'] = (phone, n, s); root.destroy()
        RoundedButton(step2, 'Продолжить →', command=fin).pack(pady=(10,0))

    finish_btn = RoundedButton(step2, 'Готово', command=on_finish)
    finish_btn.pack(pady=(10,0))

    def back1():
        step2.pack_forget()
        step1.pack(fill='both', expand=True, padx=30, pady=30)
        phone_field.focus()
    back = tk.Label(step2, text='← Назад', bg=CARD, fg=ACCENT, font=F_LINK, cursor='hand2')
    back.pack(anchor='w', pady=(12,0))
    back.bind('<Button-1>', lambda e: back1())

    def go_to_step2():
        step1.pack_forget()
        step2.pack(fill='both', expand=True, padx=30, pady=30)
        name_field.focus()

    step1.pack(fill='both', expand=True, padx=30, pady=30)
    root.mainloop()
    return result['data']
'''

# ==================== chat.py ====================
CHAT_FILE = r'''# -*- coding: utf-8 -*-
"""SnackU — чат: поиск, переписка, стикеры, история, AFK-защита."""
import tkinter as tk
from tkinter import ttk
import os, sys, re, json, time, threading, subprocess, tempfile

if r'C:\SnackU' not in sys.path:
    sys.path.insert(0, r'C:\SnackU')

from GUIREG.register import (RoundedEntry, RoundedButton,
    BG, CARD, FIELD_BG, FIELD_BORDER, TEXT, MUTED,
    ACCENT, ACCENT_HOVER, DISABLED, ERROR,
    F_TITLE, F_SUB, F_LABEL, F_BTN, F_ERR, F_LINK,
    is_valid_phone, normalize_phone)

from files32.network import (server_ping, lookup_on_server, send_heartbeat,
    send_message as net_send_message, get_messages as net_get_messages)

ICON_FILE = r'C:\SnackU\files32\icon.ico'
SX_DIR = r'C:\SnackU\SX'

# ==================== ТАЙМИНГИ ====================
HEARTBEAT_INTERVAL     = 15
STATUS_INTERVAL_ONLINE = 8
STATUS_INTERVAL_OFFLINE= 15
STATUS_INTERVAL_MIN    = 15
MESSAGES_POLL_INTERVAL = 4

ONLINE_THRESHOLD = 40
RECENT_THRESHOLD = 120

HEARTBEAT_FAIL_PAUSE = 60

# ==================== AFK ====================
AFK_TIMEOUT_SEC   = 15 * 60
AFK_CHECK_PERIOD  = 30
AFK_ERROR_CODE    = '277'
AFK_ERROR_TEXT    = 'AFK 15 MIN'

# ==================== AFK-МОНИТОР ====================
_last_activity = {'v': time.time()}
_afk_started = {'v': False}


def _bump_activity(*_args):
    _last_activity['v'] = time.time()


def _show_afk_vbs_and_exit():
    try:
        vbs_code = (
            'MsgBox "Error Code ' + AFK_ERROR_CODE + '" & vbCrLf & '
            'vbCrLf & "' + AFK_ERROR_TEXT + '", '
            'vbCritical, "SnackU"'
        )
        fname = f'snacku_afk_{int(time.time())}.vbs'
        tmp = os.path.join(tempfile.gettempdir(), fname)
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(vbs_code)
        subprocess.Popen(['wscript.exe', tmp], close_fds=True)
    except Exception as e:
        print(f'[afk] не удалось показать vbs: {e}')
    time.sleep(0.3)
    os._exit(1)


def _start_afk_watchdog():
    def loop():
        while True:
            time.sleep(AFK_CHECK_PERIOD)
            idle = time.time() - _last_activity['v']
            if idle >= AFK_TIMEOUT_SEC and not _afk_started['v']:
                _afk_started['v'] = True
                print(f'[afk] простой {int(idle)}с → выход')
                _show_afk_vbs_and_exit()
    threading.Thread(target=loop, daemon=True).start()


def _bind_activity(widget):
    widget.bind_all('<Motion>', _bump_activity, add='+')
    widget.bind_all('<KeyPress>', _bump_activity, add='+')
    widget.bind_all('<Button-1>', _bump_activity, add='+')
    widget.bind_all('<ButtonRelease-1>', _bump_activity, add='+')
    widget.bind_all('<MouseWheel>', _bump_activity, add='+')

# ==================== СТИКЕРЫ ====================
STICKERS = ['😀','😂','❤️','👍','🔥','🎉','😢','😡',
            '🤔','👋','🙏','💪','🥰','😎','🌟']


# ==================== ФАЙЛЫ КОНТАКТОВ ====================
def _find_contact_num(phone):
    if not os.path.isdir(SX_DIR):
        return None
    try:
        names = os.listdir(SX_DIR)
    except Exception:
        return None
    for name in names:
        if not (name.startswith('user_') and name.endswith('.json')):
            continue
        stem = name[len('user_'):-len('.json')]
        if not stem.isdigit():
            continue
        try:
            with open(os.path.join(SX_DIR, name), 'r', encoding='utf-8') as f:
                c = json.load(f)
            if c.get('phone') == phone:
                return int(stem)
        except Exception:
            pass
    return None


def _save_contact(contact):
    from files32.security import make_readonly, make_writable
    os.makedirs(SX_DIR, exist_ok=True)
    phone = contact.get('phone', '')

    n = 1
    while True:
        path = os.path.join(SX_DIR, f'user_{n}.json')
        if not os.path.exists(path):
            break
        try:
            with open(path, 'r', encoding='utf-8') as f:
                existing = json.load(f)
            if existing.get('phone') == phone:
                make_writable(path)
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(contact, f, ensure_ascii=False, indent=4)
                make_readonly(path)
                return path, n
        except Exception:
            pass
        n += 1

    path = os.path.join(SX_DIR, f'user_{n}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(contact, f, ensure_ascii=False, indent=4)
    try:
        make_readonly(path)
    except Exception:
        pass
    return path, n


def _load_contacts():
    contacts = []
    if not os.path.isdir(SX_DIR):
        return contacts
    try:
        names = os.listdir(SX_DIR)
    except Exception:
        return contacts
    for name in names:
        if not (name.startswith('user_') and name.endswith('.json')):
            continue
        stem = name[len('user_'):-len('.json')]
        if not stem.isdigit():
            continue
        try:
            with open(os.path.join(SX_DIR, name), 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get('phone'):
                contacts.append(data)
        except Exception:
            pass
    return contacts


# ==================== ИСТОРИЯ ====================
def _chat_txt_path(contact_num):
    return os.path.join(SX_DIR, f'chatuser_{contact_num}.txt')


def _append_to_chat_txt(contact_num, sender_surname, sender_name,
                        recipient_name, text):
    path = _chat_txt_path(contact_num)
    os.makedirs(SX_DIR, exist_ok=True)
    safe_text = text.replace('"', '\\"')
    line = (f'Messeng "{safe_text}" by '
            f'"{sender_surname} {sender_name} - {recipient_name}"\n')
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception as e:
        print(f'[txt] {e}')


_LINE_RE = re.compile(r'^Messeng "(.*)" by "(.*)"\s*$')


def _load_history(contact_num):
    path = _chat_txt_path(contact_num)
    out = []
    if not os.path.exists(path):
        return out
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for raw in f:
                raw = raw.rstrip('\n')
                m = _LINE_RE.match(raw)
                if not m:
                    continue
                text = m.group(1).replace('\\"', '"')
                who = m.group(2)
                if ' - ' in who:
                    left, right = who.split(' - ', 1)
                else:
                    left, right = who, ''
                out.append((left.strip(), right.strip(), text))
    except Exception:
        pass
    return out


# ==================== СТАТУС ====================
def _format_status(last_seen):
    if not last_seen:
        return 'не в сети', MUTED
    now = int(time.time())
    delta = now - last_seen
    if delta < ONLINE_THRESHOLD:
        return 'в сети', '#22c55e'
    if delta < RECENT_THRESHOLD:
        return 'был(а) недавно', '#eab308'
    if delta < 3600:
        return f'был(а) {delta // 60} мин назад', MUTED
    if delta < 86400:
        return f'был(а) {delta // 3600} ч назад', MUTED
    return 'не в сети', MUTED


def _start_heartbeat(phone):
    def loop():
        fails = 0
        first = True
        while True:
            try:
                ok = send_heartbeat(phone)
                if ok:
                    if first:
                        print(f'[hb] запущен (интервал {HEARTBEAT_INTERVAL}с)')
                        first = False
                    fails = 0
                else:
                    fails += 1
                    if first:
                        print('[hb] сервер не подтверждает heartbeat')
                        first = False
            except Exception as e:
                fails += 1
                if fails == 1:
                    print(f'[hb] {e}')
            st = HEARTBEAT_INTERVAL
            if fails >= 3:
                st = HEARTBEAT_FAIL_PAUSE
                print(f'[hb] сервер недоступен, пауза {HEARTBEAT_FAIL_PAUSE}с')
            time.sleep(st)
    threading.Thread(target=loop, daemon=True).start()


# ==================== ОКНО ПЕРЕПИСКИ ====================
def open_conversation(contact, owner_phone='', owner_name='', owner_surname=''):
    contact_num = _find_contact_num(contact['phone'])
    if contact_num is None:
        print(f'[!] не найден user_N.json для {contact["phone"]}')
        contact_num = 1

    win = tk.Tk()
    win.title(f'SnackU — {contact["name"]} {contact["surname"]}')
    win.geometry('500x660')
    win.configure(bg=BG)
    try:
        if os.path.exists(ICON_FILE):
            win.iconbitmap(ICON_FILE)
    except Exception:
        pass

    _bind_activity(win)

    win.update_idletasks()
    wx = (win.winfo_screenwidth() - 500) // 2
    wy = (win.winfo_screenheight() - 660) // 2
    win.geometry(f'500x660+{wx}+{wy}')

    def on_close():
        win.destroy()
    win.protocol('WM_DELETE_WINDOW', on_close)

    hdr = tk.Frame(win, bg=CARD, height=70)
    hdr.pack(fill='x')
    hdr.pack_propagate(False)

    tk.Label(hdr, text=f'{contact["name"]} {contact["surname"]}',
             bg=CARD, fg=TEXT, font=('Segoe UI', 13, 'bold')).pack(
        anchor='w', padx=15, pady=(10, 0))

    status_row = tk.Frame(hdr, bg=CARD)
    status_row.pack(anchor='w', padx=15)

    status_lbl = tk.Label(status_row, text='● ...',
                          bg=CARD, fg=MUTED, font=('Segoe UI', 9))
    status_lbl.pack(side='left')

    tk.Label(status_row, text=f'  ·  {contact["phone"]}',
             bg=CARD, fg=MUTED, font=('Segoe UI', 9)).pack(side='left')

    sticker_bar = tk.Frame(win, bg='#172033')
    sticker_bar.pack(fill='x')

    entry_holder = {}

    def _mk_sticker(emoji):
        def _click(e=None):
            e_entry = entry_holder.get('e')
            if e_entry is not None:
                e_entry.insert(tk.INSERT, emoji)
                e_entry.focus()
        lbl = tk.Label(sticker_bar, text=emoji, bg='#172033', fg='white',
                       font=('Segoe UI Emoji', 16), cursor='hand2',
                       padx=4, pady=4)
        lbl.pack(side='left')
        lbl.bind('<Button-1>', _click)

    for s in STICKERS:
        _mk_sticker(s)

    chat_frame = tk.Frame(win, bg='#1e293b')
    chat_frame.pack(fill='both', expand=True)

    scrollbar = ttk.Scrollbar(chat_frame, orient='vertical')
    scrollbar.pack(side='right', fill='y')

    chat_area = tk.Text(chat_frame, bg='#1e293b', fg=TEXT, bd=0,
                        highlightthickness=0, wrap='word',
                        font=('Segoe UI', 11), state='disabled',
                        padx=12, pady=12,
                        yscrollcommand=scrollbar.set)
    chat_area.pack(side='left', fill='both', expand=True)
    scrollbar.config(command=chat_area.yview)

    def add_msg(text, own=False, sender=''):
        chat_area.config(state='normal')
        if own:
            prefix = 'Ты: '
        elif sender:
            prefix = f'{sender}: '
        else:
            prefix = ''
        chat_area.insert('end', f'{prefix}{text}\n\n')
        chat_area.config(state='disabled')
        chat_area.see('end')

    owner_full = f'{owner_surname} {owner_name}'.strip()
    for left, right, text in _load_history(contact_num):
        if left == owner_full:
            add_msg(text, own=True)
        else:
            add_msg(text, own=False, sender=contact['name'])

    add_msg('[Система] История загружена.')

    bottom = tk.Frame(win, bg=CARD)
    bottom.pack(fill='x', side='bottom')

    entry = tk.Entry(bottom, bg=FIELD_BG, fg=TEXT,
                     insertbackground=TEXT, bd=0,
                     font=('Segoe UI', 12))
    entry.pack(side='left', fill='x', expand=True,
               padx=(10, 6), pady=10, ipady=8)
    entry_holder['e'] = entry

    def send(event=None):
        text = entry.get().strip()
        if not text:
            return

        ok, res = net_send_message(owner_phone, contact['phone'], text)
        if not ok:
            add_msg(f'[ошибка] {res}', own=True)
            return

        _append_to_chat_txt(contact_num,
                            owner_surname or '?', owner_name or '?',
                            contact['name'], text)
        add_msg(text, own=True)
        entry.delete(0, 'end')

    entry.bind('<Return>', send)

    send_btn = RoundedButton(bottom, 'Отправить', command=send,
                             width=120, height=40)
    send_btn.pack(side='right', padx=(0, 10), pady=10)

    _last_ts = {'v': int(time.time()) - 5}

    def _schedule_poll():
        win.after(MESSAGES_POLL_INTERVAL * 1000, _poll)

    def _poll():
        try:
            msgs = net_get_messages(owner_phone, contact['phone'],
                                    since=_last_ts['v'])
            for m in msgs:
                ts = int(m.get('ts', 0))
                if ts > _last_ts['v']:
                    _last_ts['v'] = ts
                if m.get('from') == contact['phone']:
                    _append_to_chat_txt(contact_num,
                                        contact.get('surname') or '?',
                                        contact.get('name') or '?',
                                        owner_name or '?',
                                        m.get('text', ''))
                    add_msg(m.get('text', ''), own=False,
                            sender=contact['name'])
        except Exception as e:
            print(f'[poll] {e}')
        _schedule_poll()

    win.after(MESSAGES_POLL_INTERVAL * 1000, _poll)

    def _schedule_status(interval_sec):
        win.after(interval_sec * 1000, _refresh_status)

    def _refresh_status():
        try:
            if win.state() == 'iconic':
                _schedule_status(STATUS_INTERVAL_MIN)
                return
        except Exception:
            pass
        try:
            u, err = lookup_on_server(contact['phone'])
            if u:
                text, color = _format_status(u.get('last_seen', 0))
                status_lbl.config(text=f'● {text}', fg=color)
                now = int(time.time())
                is_online = bool(u.get('last_seen')) and \
                            (now - u['last_seen']) < ONLINE_THRESHOLD
            elif err:
                status_lbl.config(text='● нет связи', fg=ERROR)
                is_online = False
            else:
                status_lbl.config(text='● не в сети', fg=MUTED)
                is_online = False
        except Exception as e:
            print(f'[status] {e}')
            is_online = False
        _schedule_status(STATUS_INTERVAL_ONLINE if is_online
                         else STATUS_INTERVAL_OFFLINE)

    win.after(150, _refresh_status)

    entry.focus()
    win.mainloop()


# ==================== ГЛАВНОЕ ОКНО ====================
def run_chat(phone, name, surname):
    _bump_activity()
    _start_heartbeat(phone)
    _start_afk_watchdog()

    root = tk.Tk()
    root.title('SnackU')
    root.geometry('420x620')
    root.configure(bg=BG)
    root.resizable(False, False)
    try:
        if os.path.exists(ICON_FILE): root.iconbitmap(ICON_FILE)
    except Exception: pass

    _bind_activity(root)

    root.update_idletasks()
    w,h=420,620
    x=(root.winfo_screenwidth()-w)//2
    y=(root.winfo_screenheight()-h)//2
    root.geometry(f'{w}x{h}+{x}+{y}')

    card = tk.Frame(root, bg=CARD)
    card.place(relx=0.5, rely=0.5, anchor='center', width=360, height=560)

    s1 = tk.Frame(card, bg=CARD)
    tk.Label(s1, text='Привет! 👋', bg=CARD, fg=TEXT, font=F_TITLE).pack(anchor='w', pady=(0,6))
    tk.Label(s1, text=f'Спасибо что зашёл в SnackU, {name}!',
             bg=CARD, fg=MUTED, font=F_SUB, wraplength=300,
             justify='left').pack(anchor='w', pady=(0,20))

    status_lbl = tk.Label(s1, text='● Онлайн-база SnackU', bg=CARD,
                          fg='#22c55e', font=('Segoe UI', 8))
    status_lbl.pack(anchor='w', pady=(0,15))

    tk.Label(s1, text='Добавьте Первый Чат!', bg=CARD, fg=TEXT,
             font=('Segoe UI', 14, 'bold')).pack(anchor='w', pady=(0,16))
    tk.Label(s1, text='Номер телефона', bg=CARD, fg=MUTED, font=F_LABEL).pack(anchor='w', pady=(0,6))

    pf = RoundedEntry(s1, placeholder='+7 999 123-45-67', numeric_only=True)
    pf.pack(fill='x')

    info = tk.Label(s1, text='', bg=CARD, fg=ERROR, font=F_ERR,
                    anchor='w', wraplength=300, justify='left')
    info.pack(fill='x', pady=(6,12))

    _aid = {'id': None}

    def _check():
        v = pf.get().strip()
        if v == '':
            info.config(text=''); return
        ok, cleaned, err = is_valid_phone(v)
        if not ok:
            info.config(text=err, fg=ERROR); return
        if cleaned == phone:
            info.config(text='Это ваш номер 🙂', fg=ERROR); return
        info.config(text='Поиск...', fg=MUTED); root.update_idletasks()
        found, error = lookup_on_server(cleaned)
        if error:
            info.config(text=error, fg=ERROR); return
        if found:
            info.config(text=f'Найден: {found["name"]} {found["surname"]}', fg='#22c55e')
        else:
            info.config(text='Введи Номер Который Ввел в SnackU!', fg=ERROR)

    def on_ch():
        if _aid['id']:
            try: root.after_cancel(_aid['id'])
            except Exception: pass
        _aid['id'] = root.after(700, _check)

    pf.set_on_change(on_ch)

    def cont():
        v = pf.get().strip()
        ok, cleaned, err = is_valid_phone(v)
        if not ok:
            info.config(text=err or 'Введите номер', fg=ERROR); return
        if cleaned == phone:
            info.config(text='Это ваш номер 🙂', fg=ERROR); return
        info.config(text='Поиск...', fg=MUTED); root.update_idletasks()
        found, error = lookup_on_server(cleaned)
        if error:
            info.config(text=error, fg=ERROR); return
        if not found:
            info.config(text='Введи Номер Который Ввел в SnackU!', fg=ERROR); return
        show_confirm(found)

    RoundedButton(s1, 'Продолжить', command=cont).pack(side='bottom', pady=(10,0))

    s2 = tk.Frame(card, bg=CARD)
    tk.Label(s2, text='Это Он(а)?', bg=CARD, fg=TEXT, font=F_TITLE).pack(anchor='w', pady=(0,25))
    nm = tk.Label(s2, text='', bg=CARD, fg=TEXT, font=('Segoe UI', 20, 'bold'))
    nm.pack(anchor='w', pady=(0,6))
    ph = tk.Label(s2, text='', bg=CARD, fg=MUTED, font=('Segoe UI', 10))
    ph.pack(anchor='w', pady=(0,30))

    _cur = {'d': None}
    _handoff = {'contact': None}

    def on_add():
        c = _cur['d']
        if not c:
            return
        try:
            path, num = _save_contact(c)
            print(f'[chat] контакт сохранён: {path}')
        except Exception as e:
            print(f'[!] ошибка сохранения контакта: {e}')
        _handoff['contact'] = c
        root.destroy()

    RoundedButton(s2, 'Да, добавить', command=on_add).pack(pady=(10,8))

    def back_e():
        s2.pack_forget()
        s1.pack(fill='both', expand=True, padx=30, pady=30)
        pf.focus()
    bl = tk.Label(s2, text='← Изменить номер', bg=CARD, fg=ACCENT,
                  font=F_LINK, cursor='hand2')
    bl.pack(anchor='w', pady=(4,0))
    bl.bind('<Button-1>', lambda e: back_e())

    def show_confirm(u):
        _cur['d'] = u
        nm.config(text=f'{u["name"]} {u["surname"]}')
        ph.config(text=u['phone'])
        s1.pack_forget()
        s2.pack(fill='both', expand=True, padx=30, pady=30)

    s1.pack(fill='both', expand=True, padx=30, pady=30)
    pf.focus()
    root.mainloop()

    if _handoff['contact'] is not None:
        open_conversation(_handoff['contact'],
                          owner_phone=phone,
                          owner_name=name,
                          owner_surname=surname)
'''


# ==================== ХЕЛПЕРЫ ====================

def write_file(path, content):
    if os.path.exists(path):
        try:
            subprocess.run(['attrib','-R','-H','-S',path],
                           shell=True, capture_output=True, check=False)
        except Exception: pass
        try: os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except Exception: pass
        try:
            user = os.environ.get('USERNAME','')
            if user:
                subprocess.run(['icacls', path, '/remove:d', user],
                               shell=True, capture_output=True, check=False)
        except Exception: pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def get_desktop():
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        ctypes.windll.shell32.SHGetFolderPathW(None, 0x0010, None, 0, buf)
        if buf.value: return buf.value
    except Exception: pass
    return os.path.join(os.path.expanduser('~'), 'Desktop')


def create_shortcut():
    desktop = get_desktop()
    lnk = os.path.join(desktop, 'SnackU.lnk')
    exe = sys.executable
    args = ''

    if not getattr(sys, 'frozen', False):
        pyw = exe[:-len('python.exe')] + 'pythonw.exe' if exe.lower().endswith('python.exe') else exe
        if os.path.exists(pyw):
            exe = pyw
        script = os.path.abspath(__file__)
        args = f'"{script}"' if ' ' in script else script
    else:
        args = ''

    wd = os.path.dirname(exe)

    def ps_q(s):
        return s.replace("'", "''")

    ps = (
        f"$ws = New-Object -ComObject WScript.Shell;"
        f"$s = $ws.CreateShortcut('{ps_q(lnk)}');"
        f"$s.TargetPath = '{ps_q(exe)}';"
        f"$s.Arguments = '{ps_q(args)}';"
        f"$s.WorkingDirectory = '{ps_q(wd)}';"
        f"$s.IconLocation = '{ps_q(exe)},0';"
        f"$s.Description = 'SnackU Messenger';"
        f"$s.Save();"
    )

    r = subprocess.run(
        ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
        capture_output=True, check=False
    )

    if r.returncode != 0:
        err = r.stderr.decode('cp866', errors='replace') or r.stderr.decode('utf-8', errors='replace')
        print(f'[!] ярлык не создан: {err}')
        print(f'[i] Создай ярлык вручную: ПКМ по SnackU.py → Отправить → Рабочий стол')
    else:
        print(f'[ярлык] {lnk}')


def install():
    print(f'Установка SnackU в: {BASE}\n')
    folders = [
        BASE,
        os.path.join(BASE, 'files32'),
        os.path.join(BASE, 'GUI'),
        os.path.join(BASE, 'GUIREG'),
        os.path.join(BASE, 'Messeng'),
        os.path.join(BASE, 'Messeng', 'MessengGUI'),
        os.path.join(BASE, 'SX'),
    ]
    for f in folders:
        os.makedirs(f, exist_ok=True)
        print(f'[+] {f}')

    write_file(os.path.join(BASE, 'GUI', '__init__.py'), INIT_FILE)
    write_file(os.path.join(BASE, 'GUIREG', '__init__.py'), INIT_FILE)
    write_file(os.path.join(BASE, 'Messeng', '__init__.py'), INIT_FILE)
    write_file(os.path.join(BASE, 'Messeng', 'MessengGUI', '__init__.py'), INIT_FILE)
    write_file(os.path.join(BASE, 'files32', '__init__.py'), INIT_FILE)

    write_file(os.path.join(BASE, 'files32', 'main.py'), MAIN_FILE)
    write_file(os.path.join(BASE, 'files32', 'security.py'), SECURITY_FILE)
    write_file(os.path.join(BASE, 'files32', 'network.py'), NETWORK_FILE)
    write_file(os.path.join(BASE, 'GUIREG', 'register.py'), REGISTER_FILE)
    write_file(os.path.join(BASE, 'Messeng', 'MessengGUI', 'chat.py'), CHAT_FILE)

    print('\n[защита]...')
    sys.path.insert(0, os.path.join(BASE, 'files32'))
    try:
        from security import protect_all, save_integrity
        save_integrity(); protect_all()
    except Exception as e:
        print(f'[!] {e}')

    create_shortcut()
    print(f'\n✅ Готово!')
    print(f'   Папка: {BASE}')
    print(f'   Запускай через ярлык "SnackU" на рабочем столе.')


def launch_app():
    sys.path.insert(0, BASE)
    import runpy
    runpy.run_path(INSTALL_FLAG, run_name='__main__')


def main():
    if '--install' in sys.argv:
        install(); return
    if '--launch' in sys.argv:
        if not os.path.exists(INSTALL_FLAG): install()
        launch_app(); return
    if os.path.exists(INSTALL_FLAG):
        launch_app()
    else:
        install()


if __name__ == '__main__':
    main()
