# -*- coding: utf-8 -*-
"""
SnackU API — регистрация, поиск, heartbeat, сообщения.
Шардинг:
  • юзеры:     user_1.json .. user_4.json  (шард = hash(phone) mod 4)
  • сообщения: msg_1.json  .. msg_4.json   (шард = hash(channel) mod 4)
"""
from http.server import BaseHTTPRequestHandler
import json
import os
import re
import time
import base64
import hashlib
import logging
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('snacku')

# ==================== НАСТРОЙКИ ====================
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
GITHUB_OWNER = os.environ.get('GITHUB_OWNER', '')
GITHUB_REPO  = os.environ.get('GITHUB_REPO', '')
GITHUB_BRANCH = os.environ.get('GITHUB_BRANCH', 'main')

ALLOW_OVERWRITE = (
    os.environ.get('ALLOW_OVERWRITE', 'false').lower() == 'true'
    and os.environ.get('VERCEL_ENV', '') != 'production'
)

# ==================== ШАРДИНГ ====================
USER_SHARD_PREFIX = 'user_'
MSG_SHARD_PREFIX  = 'msg_'
SHARD_SUFFIX      = '.json'

# ⚠️ НЕ МЕНЯТЬ после релиза!
# Если поменять с 4 на 8 — все зарегистрированные номера "переедут"
# в другие шарды, и API их не найдёт.
SHARD_COUNT = 4

MAX_MSGS_PER_CHANNEL = 500

MAX_RETRIES = 2
RETRY_DELAY = 0.3
REQUEST_TIMEOUT = 3


def _shard_hash(s):
    return int(hashlib.md5(s.encode('utf-8')).hexdigest(), 16)


def _user_shard(phone):
    return (_shard_hash('u:' + phone) % SHARD_COUNT) + 1


def _channel_key(a, b):
    x, y = sorted([a, b])
    return f'{x}|{y}'


def _msg_shard(a, b):
    return (_shard_hash('m:' + _channel_key(a, b)) % SHARD_COUNT) + 1


def _user_url(n):
    return (f'https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}'
            f'/contents/{USER_SHARD_PREFIX}{n}{SHARD_SUFFIX}')


def _msg_url(n):
    return (f'https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}'
            f'/contents/{MSG_SHARD_PREFIX}{n}{SHARD_SUFFIX}')


# ==================== ВАЛИДАЦИЯ ====================
PHONE_RE = re.compile(r'^\+7\d{10}$')
NAME_RE  = re.compile(r"^[А-Яа-яЁёA-Za-z]+(?:[-'\s][А-Яа-яЁёA-Za-z]+)*$")

MAX_NAME_LEN = 50
MAX_PHONE_LEN = 12


def normalize_phone(phone):
    return re.sub(r'[\s\-\(\)]', '', phone or '')


def is_valid_phone_ru(phone):
    cleaned = normalize_phone(phone)
    if not cleaned or len(cleaned) > MAX_PHONE_LEN:
        return False, '', 'invalid_phone'
    if not PHONE_RE.match(cleaned):
        return False, '', 'invalid_phone'
    digits = cleaned[2:]
    if len(set(digits)) == 1:
        return False, '', 'invalid_phone'
    if digits[0] in ('0', '7'):
        return False, '', 'invalid_phone'
    return True, cleaned, ''


def validate_register(phone, name, surname):
    ok, cleaned, err = is_valid_phone_ru(phone)
    if not ok:
        return False, '', err
    if not name or not surname:
        return False, '', 'empty_name'
    if len(name) > MAX_NAME_LEN or len(surname) > MAX_NAME_LEN:
        return False, '', 'name_too_long'
    if not NAME_RE.match(name):
        return False, '', 'invalid_name'
    if not NAME_RE.match(surname):
        return False, '', 'invalid_name'
    return True, cleaned, ''


class GhError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(message)


# ==================== GitHub API ====================
def _gh_request(method, url, data=None):
    req = urllib.request.Request(url, method=method)
    req.add_header('Authorization', f'token {GITHUB_TOKEN}')
    req.add_header('Accept', 'application/vnd.github+json')
    req.add_header('User-Agent', 'SnackU')
    if data is not None:
        req.add_header('Content-Type', 'application/json')
        body = json.dumps(data).encode('utf-8')
    else:
        body = None
    with urllib.request.urlopen(req, data=body, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode('utf-8'))


def gh_read_json(url):
    try:
        result = _gh_request('GET', f'{url}?ref={GITHUB_BRANCH}')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None
        raise
    content = base64.b64decode(result['content']).decode('utf-8')
    data = json.loads(content) if content.strip() else {}
    return data, result['sha']


def gh_write_json(url, data, sha=None, commit_msg='SnackU update'):
    content = json.dumps(data, ensure_ascii=False, indent=2)
    encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    payload = {
        'message': commit_msg,
        'content': encoded,
        'branch': GITHUB_BRANCH,
    }
    if sha:
        payload['sha'] = sha
    return _gh_request('PUT', url, payload)


def _classify_http_error(e):
    code = e.code
    if code == 401:
        return False, 'bad_token'
    if code == 403:
        remaining = (e.headers.get('X-RateLimit-Remaining') or '1').strip()
        if remaining == '0':
            return False, 'rate_limit'
        return False, 'forbidden'
    if code == 404:
        return False, 'not_found'
    if code == 409:
        return True, 'conflict'
    if code == 422:
        return True, 'unprocessable'
    if 500 <= code < 600:
        return True, f'github_{code}'
    return False, f'http_{code}'


def do_with_retries(action_fn):
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return True, action_fn(), 200
        except GhError as e:
            return False, e.message, e.code
        except urllib.error.HTTPError as e:
            retry, err_code = _classify_http_error(e)
            last_err = err_code
            log.warning(f'gh http {e.code} attempt={attempt}: {err_code}')
            if not retry:
                return False, last_err, 503
        except urllib.error.URLError as e:
            last_err = f'network: {e.reason}'
            log.warning(f'net err attempt={attempt}: {last_err}')
        except Exception as e:
            last_err = f'error: {type(e).__name__}'
            log.warning(f'err attempt={attempt}: {last_err}')
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY * attempt)
    return False, last_err or 'unknown', 503


# ==================== ЮЗЕРЫ ====================
def _load_user_shard(n):
    return gh_read_json(_user_url(n))


def _save_user_shard(n, data, sha):
    gh_write_json(_user_url(n), data, sha=sha,
                  commit_msg=f'SnackU: user shard {n}')


def register_user(phone, name, surname):
    def _do():
        n = _user_shard(phone)
        data, sha = _load_user_shard(n)
        if data is None:
            data = {}
            sha = None

        if phone in data:
            if not ALLOW_OVERWRITE:
                raise GhError(409, 'already_registered')

        data[phone] = {
            'name': name,
            'surname': surname,
            'last_seen': int(time.time()),
        }
        _save_user_shard(n, data, sha)
        return {'phone': phone, 'shard': n}
    return do_with_retries(_do)


def lookup_user(phone):
    def _do():
        n = _user_shard(phone)
        data, _ = _load_user_shard(n)
        if not data:
            return None
        return data.get(phone)
    return do_with_retries(_do)


def heartbeat_user(phone):
    def _do():
        n = _user_shard(phone)
        data, sha = _load_user_shard(n)
        if not data or phone not in data:
            raise GhError(404, 'not_registered')
        data[phone]['last_seen'] = int(time.time())
        _save_user_shard(n, data, sha)
        return {'phone': phone, 'last_seen': data[phone]['last_seen']}
    return do_with_retries(_do)


# ==================== СООБЩЕНИЯ ====================
def _load_msg_shard(n):
    return gh_read_json(_msg_url(n))


def _save_msg_shard(n, data, sha):
    gh_write_json(_msg_url(n), data, sha=sha,
                  commit_msg=f'SnackU: msg shard {n}')


def send_message(from_phone, to_phone, text):
    def _do():
        text_clean = (text or '').strip()
        if not text_clean:
            raise GhError(400, 'empty_text')
        if len(text_clean) > 1000:
            raise GhError(400, 'text_too_long')

        from_shard = _user_shard(from_phone)
        to_shard = _user_shard(to_phone)

        from_data, _ = _load_user_shard(from_shard)
        if not from_data or from_phone not in from_data:
            raise GhError(404, 'not_registered')

        to_data, _ = _load_user_shard(to_shard)
        if not to_data or to_phone not in to_data:
            raise GhError(404, 'receiver_not_found')

        n = _msg_shard(from_phone, to_phone)
        data, sha = _load_msg_shard(n)
        if data is None:
            data = {}
            sha = None

        key = _channel_key(from_phone, to_phone)
        arr = data.setdefault(key, [])
        if len(arr) >= MAX_MSGS_PER_CHANNEL:
            arr[:] = arr[-(MAX_MSGS_PER_CHANNEL - 1):]

        msg = {'from': from_phone, 'text': text_clean, 'ts': int(time.time())}
        arr.append(msg)

        _save_msg_shard(n, data, sha)
        return msg
    return do_with_retries(_do)


def get_messages(from_phone, to_phone, since=0):
    def _do():
        n = _msg_shard(from_phone, to_phone)
        data, _ = _load_msg_shard(n)
        if not data:
            return []
        key = _channel_key(from_phone, to_phone)
        arr = data.get(key, [])
        return [m for m in arr if int(m.get('ts', 0)) > int(since)]
    return do_with_retries(_do)


# ==================== СООБЩЕНИЯ ОБ ОШИБКАХ ====================
ERROR_MESSAGES = {
    'rate_limit':         'Сервер Перегружен Попробуйте ещё Раз',
    'conflict':           'Сервер Перегружен Попробуйте ещё Раз',
    'unprocessable':      'Сервер Перегружен Попробуйте ещё Раз',
    'forbidden':          'Ошибка настройки сервера (нет прав токена)',
    'bad_token':          'Ошибка настройки сервера (неверный токен)',
    'not_found':          'Ошибка настройки сервера (файл не найден)',
    'already_registered': 'Номер уже зарегистрирован',
    'not_registered':     'Пользователь не найден',
    'receiver_not_found': 'Получатель не найден',
    'empty_text':         'Пустое сообщение',
    'text_too_long':      'Сообщение слишком длинное',
    'invalid_phone':      'Невалидный номер',
    'invalid_name':       'Невалидное имя или фамилия',
    'empty_name':         'Пустое имя или фамилия',
    'name_too_long':      'Имя или фамилия слишком длинные',
}


def _msg_for(err_code):
    if err_code in ERROR_MESSAGES:
        return ERROR_MESSAGES[err_code]
    if err_code and err_code.startswith(('network:', 'error:', 'github_')):
        return 'Сервер Перегружен Попробуйте ещё Раз'
    return 'Ошибка: ' + (err_code or 'unknown')


# ==================== HANDLER ====================
class handler(BaseHTTPRequestHandler):

    def _send_json(self, code, payload):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8')
            req = json.loads(body)
        except Exception:
            self._send_json(400, {'error': 'bad request'})
            return

        action = req.get('action')

        if action == 'register':
            phone_raw = (req.get('phone') or '').strip()
            name    = (req.get('name') or '').strip()
            surname = (req.get('surname') or '').strip()

            ok, phone, err = validate_register(phone_raw, name, surname)
            if not ok:
                self._send_json(400, {
                    'status': 'error',
                    'message': _msg_for(err),
                    'detail': err,
                })
                return

            ok, result, code = register_user(phone, name, surname)
            if ok:
                self._send_json(200, {'status': 'ok', 'phone': phone})
            else:
                self._send_json(code, {
                    'status': 'error',
                    'message': _msg_for(result),
                    'detail': result,
                })

        elif action == 'lookup':
            ok, phone, err = is_valid_phone_ru(req.get('phone'))
            if not ok:
                self._send_json(400, {'error': 'invalid phone'})
                return

            ok, result, code = lookup_user(phone)
            if not ok:
                self._send_json(code, {
                    'status': 'error',
                    'message': _msg_for(result),
                    'detail': result,
                })
            elif result:
                self._send_json(200, {
                    'status': 'ok',
                    'found': True,
                    'user': {
                        'phone': phone,
                        'name': result.get('name', ''),
                        'surname': result.get('surname', ''),
                        'last_seen': result.get('last_seen', 0),
                    },
                })
            else:
                self._send_json(200, {'status': 'ok', 'found': False})

        elif action == 'heartbeat':
            ok, phone, err = is_valid_phone_ru(req.get('phone'))
            if not ok:
                self._send_json(400, {'error': 'invalid phone'})
                return

            ok, result, code = heartbeat_user(phone)
            if ok:
                self._send_json(200, {
                    'status': 'ok',
                    'last_seen': result.get('last_seen', 0),
                })
            else:
                self._send_json(code, {
                    'status': 'error',
                    'message': _msg_for(result),
                    'detail': result,
                })

        elif action == 'send_message':
            ok1, from_phone, _ = is_valid_phone_ru(req.get('from'))
            ok2, to_phone, _ = is_valid_phone_ru(req.get('to'))
            if not ok1 or not ok2:
                self._send_json(400, {'error': 'invalid phone'})
                return
            text = req.get('text', '')

            ok, result, code = send_message(from_phone, to_phone, text)
            if ok:
                self._send_json(200, {'status': 'ok', 'message': result})
            else:
                self._send_json(code, {
                    'status': 'error',
                    'message': _msg_for(result),
                    'detail': result,
                })

        elif action == 'get_messages':
            ok1, from_phone, _ = is_valid_phone_ru(req.get('from'))
            ok2, to_phone, _ = is_valid_phone_ru(req.get('to'))
            if not ok1 or not ok2:
                self._send_json(400, {'error': 'invalid phone'})
                return
            try:
                since = int(req.get('since', 0))
            except Exception:
                since = 0

            ok, result, code = get_messages(from_phone, to_phone, since)
            if ok:
                self._send_json(200, {'status': 'ok', 'messages': result})
            else:
                self._send_json(code, {
                    'status': 'error',
                    'message': _msg_for(result),
                    'detail': result,
                })

        else:
            self._send_json(400, {'error': 'unknown action'})
