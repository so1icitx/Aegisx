from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from argon2 import PasswordHasher
from dotenv import load_dotenv
from datetime import timedelta, datetime # Added datetime import
import sqlite3, os, secrets, time
import threading
import time as time_module
import csv
import io
import base64
import pyotp
import qrcode
from io import BytesIO
import re
import hashlib
import requests
from urllib.parse import urlparse # Added for passkey URL parsing

# Import custom utility modules
from lib.db_utils import fetch_all_passwords, get_db_connection
from lib.fuzzy_search import search_passwords as fuzzy_search_passwords
from lib.darkweb_monitor import check_password_breach, check_email_breach, init_breach_cache_db
from lib.trash_manager import (
    get_all_trash_items,
    get_trash_item_by_id,
    restore_from_trash,
    delete_permanent,
    empty_trash,
    auto_delete_trash_on_login
)
from lib.encryption import init_secret_key, encrypt_data, decrypt_data
from lib.password_utils import create_password, check_password_strength
from lib.security_analysis import analyze_password_security
from lib.auth import (
    generate_csrf_token,
    verify_csrf_token,
    check_2fa_enabled,
    verify_2fa_code,
    generate_2fa_qr,
    enable_2fa,
    disable_2fa
)
from lib.translations import TRANSLATIONS, get_translation_function
from lib.import_export import import_passwords_from_file, export_passwords
from lib.session_manager import enforce_session_timeout
from lib.db_operations import init_db, migrate_db
from lib.clipboard_manager import clipboard_timers, clear_clipboard_after_delay
from lib.route_helpers import format_entry_dates, get_passkey_opportunities

# ============================================================
#  Translations
# ============================================================
# Multi-language support dictionary (English and Bulgarian)
TRANSLATIONS = {
    'en': {
        # Dashboard
        'dashboard': 'Dashboard',
        'passwords': 'Passwords',
        'allItems': 'All Items',
        'cards': 'Cards',
        'notes': 'Notes',
        'settings': 'Settings',
        'logout': 'Logout',
        'searchAllItems': 'Search in all items...',
        'filters': 'Filters',
        'filterBy': 'Filter by',
        'allPasswords': 'All Passwords',
        'weakPasswords': 'Weak Passwords',
        'vulnerablePasswords': 'Vulnerable Passwords',
        'duplicatePasswords': 'Duplicate Passwords',
        'favoritesOnly': 'Favorites Only',
        'recentlyModified': 'Recently Modified',
        'createItem': 'Create item',
        'addPassword': 'Add Password',
        'noPasswordsFound': 'No passwords found',
        'noPasswordsSaved': 'No passwords saved yet',
        'clickCreateItem': 'Click Create item to add your first password',
        'noPasswordsMessage': 'Add your first password to get started',
        'selectPassword': 'Select a password to view details',
        'title': 'Title',
        'username': 'Username',
        'password': 'Password',
        'url': 'URL',
        'category': 'Category',
        'lastModified': 'Last Modified',
        'firstCreated': 'First Created',
        'created': 'Created',
        'copyPassword': 'Copy Password',
        'copyUsername': 'Copy Username',
        'copyTOTP': 'Copy TOTP',
        'edit': 'Edit',
        'delete': 'Delete',
        'confirmDelete': 'Are you sure you want to delete this password?',
        'addToFavorites': 'Add to favorites',
        'removeFromFavorites': 'Remove from favorites',
        'passwordHistory': 'Password History',
        'noHistory': 'No password history available',
        'noHistoryAvailable': 'No history available',
        'changedOn': 'Changed on',
        'clickToCopy': 'Click to copy',
        'itemsSelected': 'items selected',
        'bulkDelete': 'Delete',
        'bulkExport': 'Export',
        'cancel': 'Cancel',
        'save': 'Save',
        'saving': 'Saving...',
        'trash': 'Trash',
        'restore': 'Restore',
        'emptyTrash': 'Empty Trash',
        'permanentDelete': 'Permanently Delete',
        'deletePermanently': 'Are you sure you want to permanently delete this item? This action cannot be undone.',
        'restoreItem': 'Are you sure you want to restore this item?',
        'emptyTrashConfirm': 'Are you sure you want to permanently delete all items in the trash?',
        'trashEmpty': 'Trash is empty.',
        'autoDeleteTrash': 'Automatically delete items from trash after',
        'days': 'days',
        'autoDeleteTrashHint': 'Items in the trash will be permanently deleted after this period.',
        'trashItemCount': '{count} item(s) in trash',
        'noTrashItems': 'No items in trash.',
        'restoreAll': 'Restore All',

        # Passkey Support
        'passkeySupport': 'Passkey Support',
        'checkPasskeySupport': 'Check Passkey Support',
        'passkeySupported': 'This site supports passkeys!',
        'passkeyNotSupported': 'Passkeys are not yet supported on this site.',
        'passkeyCheckInProgress': 'Checking passkey support...',
        'passkeyDetails': 'Passkey Details',
        'passkeyAvailable': 'Passkey Available',
        'passkeyNotAvailable': 'Passkey Not Available',
        'passkeyLastChecked': 'Last Checked',
        'convertedToPasskey': 'Converted to Passkey',
        'noPasskeyYet': 'No Passkey Yet',
        'passkeyOpportunities': 'Passkey Opportunities',
        'passkeyOpportunityCount': '{count} opportunities found to switch to passkeys.',
        'learnMore': 'Learn More',


        # Add/Edit forms
        'addNewPassword': 'Add New Entry',
        'editPassword': 'Edit Entry',
        'titlePlaceholder': 'My Account',
        'usernamePlaceholder': 'username',
        'passwordPlaceholder': 'Enter password',
        'urlPlaceholder': 'https://example.com',
        'totpPlaceholder': 'Base32 secret key',
        'selectCategory': 'Select category',
        'addCustomCategory': '+ Add Custom Category',
        'customCategoryPlaceholder': 'Enter category name',
        'enterCategoryName': 'Enter category name',
        'personal': 'Personal',
        'work': 'Work',
        'banking': 'Banking',
        'socialMedia': 'Social Media',
        'shopping': 'Shopping',
        'entertainment': 'Entertainment',
        'other': 'Other',
        'generatePassword': 'Generate',
        'passwordStrength': 'Password Strength',
        'strong': 'Strong',
        'vulnerable': 'Vulnerable',
        'weak': 'Weak',
        'breached': 'Breached',
        'usePassword': 'Use Password',
        'passwordGenerator': 'Password Generator',
        'adjustSettings': 'Adjust settings to generate',
        'length': 'Length',
        'uppercase': 'Uppercase (A-Z)',
        'lowercase': 'Lowercase (a-z)',
        'numbers': 'Numbers (0-9)',
        'symbols': 'Symbols (!@#$...)',

        # Categories
        'uncategorized': 'Uncategorized',

        # Settings
        'settingsTitle': 'Settings',
        'managePreferences': 'Manage your AegisX preferences and data',
        'import': 'Import',
        'export': 'Export',
        'preferences': 'Preferences',
        'security': 'Security',
        'support': 'Support',
        'importPasswords': 'Import Passwords',
        'selectPasswordManager': 'Select your password manager to import your passwords into AegisX.',
        'exportPasswords': 'Export Passwords',
        'exportDescription': 'Export your passwords in various formats for backup or migration.',
        'preferencesTitle': 'Preferences',
        'customizeExperience': 'Customize your AegisX experience.',
        'securityTitle': 'Security',
        'manageSecuritySettings': 'Manage security settings for your AegisX vault.',
        'twoFactorAuth': 'Two-Factor Authentication',
        'add2FALayer': 'Add an extra layer of security with 2FA.',
        'enable2FA': 'Enable 2FA',
        'disable2FA': 'Disable 2FA',
        'language': 'Language',
        'chooseLanguage': 'Choose your preferred language.',
        'theme': 'Theme',
        'chooseTheme': 'Choose your preferred color scheme.',
        'autoLock': 'Auto-Lock Timeout',
        'autoLockDescription': 'Automatically lock AegisX after a period of inactivity.',
        'lightMode': 'Light',
        'darkMode': 'Dark',
        'systemMode': 'System',
        'brightAndClean': 'Bright and clean',
        'easyOnEyes': 'Easy on the eyes',
        'matchDevice': 'Match device',
        'savePreferences': 'Save Preferences',
        'json': 'JSON',
        'csv': 'CSV',
        'pgpEncrypted': 'PGP Encrypted',
        'structuredDataFormat': 'Structured data format',
        'spreadsheetFormat': 'Spreadsheet format',
        'passwordProtected': 'Password-protected',
        'encryptionPassword': 'Encryption password',
        'exportPGP': 'Export PGP',
        'exportNote': 'JSON and CSV exports contain unencrypted passwords. Store them securely. PGP export is encrypted with your chosen password.',
        'note': 'Note',
        'securityDashboard': 'Security Dashboard',
        'passwordBreached': 'Password Breached',
        'passwordBreachedDescription': 'This password has appeared in a known data breach.',
        'passwordDuplicates': 'Duplicate Passwords',
        'passwordDuplicatesDescription': 'These passwords are used for multiple accounts.',
        'passwordWeak': 'Weak Passwords',
        'passwordWeakDescription': 'These passwords are too simple and easy to guess.',
        'passwordVulnerable': 'Vulnerable Passwords',
        'passwordVulnerableDescription': 'These passwords could be stronger.',
        'strongPasswords': 'Strong Passwords',
        'weakPasswords': 'Weak Passwords',
        'breachedPasswords': 'Breached Passwords',
        'duplicatePasswords': 'Duplicate Passwords',
        'totalEntries': 'Total Entries',
        'analyze': 'Analyze',
        'analyzing': 'Analyzing...',
        'securityScore': 'Security Score',
        'good': 'Good',
        'fair': 'Fair',
        'poor': 'Poor',
        'unrated': 'Unrated',
        'actionRequired': 'Action Required',
        'viewAll': 'View All',
        'noSecurityIssues': 'No security issues found!',
        'allPasswordsSecure': 'All your passwords are secure.',
        'checkNow': 'Check Now',
        'emailBreached': 'Email Breached',
        'emailBreachedDescription': 'This email address has appeared in known data breaches.'
    },
    'bg': {
        # Dashboard
        'dashboard': 'Табло',
        'passwords': 'Пароли',
        'allItems': 'Всички елементи',
        'cards': 'Карти',
        'notes': 'Бележки',
        'settings': 'Настройки',
        'logout': 'Изход',
        'searchAllItems': 'Търсене във всички елементи...',
        'filters': 'Филтри',
        'filterBy': 'Филтриране по',
        'allPasswords': 'Всички пароли',
        'weakPasswords': 'Слаби пароли',
        'vulnerablePasswords': 'Уязвими пароли',
        'duplicatePasswords': 'Дублирани пароли',
        'favoritesOnly': 'Само любими',
        'recentlyModified': 'Наскоро променени',
        'createItem': 'Създай елемент',
        'addPassword': 'Добави парола',
        'noPasswordsFound': 'Няма намерени пароли',
        'noPasswordsSaved': 'Все още няма запазени пароли',
        'clickCreateItem': 'Кликнете Създай елемент, за да добавите първата си парола',
        'noPasswordsMessage': 'Добавете първата си парола, за да започнете',
        'selectPassword': 'Изберете парола, за да видите детайли',
        'title': 'Заглавие',
        'username': 'Потребителско име',
        'password': 'Парола',
        'url': 'URL адрес',
        'category': 'Категория',
        'lastModified': 'Последна промяна',
        'firstCreated': 'Първо създаване',
        'created': 'Създадена',
        'copyPassword': 'Копирай парола',
        'copyUsername': 'Копирай потребителско име',
        'copyTOTP': 'Копирай TOTP',
        'edit': 'Редактирай',
        'delete': 'Изтрий',
        'confirmDelete': 'Сигурни ли сте, че искате да изтриете тази парола?',
        'addToFavorites': 'Добави към любими',
        'removeFromFavorites': 'Премахни от любими',
        'passwordHistory': 'История на паролата',
        'noHistory': 'Няма налична история на паролата',
        'noHistoryAvailable': 'Няма налична история',
        'changedOn': 'Променена на',
        'clickToCopy': 'Кликнете за копиране',
        'itemsSelected': 'избрани елемента',
        'bulkDelete': 'Изтрий',
        'bulkExport': 'Експортирай',
        'cancel': 'Отказ',
        'save': 'Запази',
        'saving': 'Записване...',
        'trash': 'Кошче',
        'restore': 'Възстанови',
        'emptyTrash': 'Изпразни кошчето',
        'permanentDelete': 'Изтрий завинаги',
        'deletePermanently': 'Сигурни ли сте, че искате завинаги да изтриете този елемент? Тази операция не може да бъде отменена.',
        'restoreItem': 'Сигурни ли сте, че искате да възстановите този елемент?',
        'emptyTrashConfirm': 'Сигурни ли сте, че искате да изтриете завинаги всички елементи в кошчето?',
        'trashEmpty': 'Кошчето е празно.',
        'autoDeleteTrash': 'Автоматично изтриване на елементи от кошчето след',
        'days': 'дни',
        'autoDeleteTrashHint': 'Елементите в кошчето ще бъдат трайно изтрити след този период.',
        'trashItemCount': '{count} елемент(а) в кошчето',
        'noTrashItems': 'Няма елементи в кошчето.',
        'restoreAll': 'Възстанови всички',

        # Passkey Support
        'passkeySupport': 'Поддръжка на Passkey',
        'checkPasskeySupport': 'Провери поддръжката на Passkey',
        'passkeySupported': 'Този сайт поддържа passkeys!',
        'passkeyNotSupported': 'Passkeys все още не се поддържат на този сайт.',
        'passkeyCheckInProgress': 'Проверява се поддръжката на passkey...',
        'passkeyDetails': 'Детайли за Passkey',
        'passkeyAvailable': 'Passkey наличен',
        'passkeyNotAvailable': 'Passkey не е наличен',
        'passkeyLastChecked': 'Последно проверен',
        'convertedToPasskey': 'Конвертиран към Passkey',
        'noPasskeyYet': 'Все още няма Passkey',
        'passkeyOpportunities': 'Възможности за Passkey',
        'passkeyOpportunityCount': 'Намерени {count} възможности за преминаване към passkeys.',
        'learnMore': 'Научи повече',

        # Add/Edit forms
        'addNewPassword': 'Добави нов запис',
        'editPassword': 'Редактирай запис',
        'titlePlaceholder': 'Моят акаунт',
        'usernamePlaceholder': 'потребителско име',
        'passwordPlaceholder': 'Въведете парола',
        'urlPlaceholder': 'https://example.com',
        'totpPlaceholder': 'Base32 секретен ключ',
        'selectCategory': 'Изберете категория',
        'addCustomCategory': '+ Добави персонализирана категория',
        'customCategoryPlaceholder': 'Въведете име на категория',
        'enterCategoryName': 'Въведете име на категория',
        'personal': 'Лични',
        'work': 'Работа',
        'banking': 'Банкиране',
        'socialMedia': 'Социални мрежи',
        'shopping': 'Пазаруване',
        'entertainment': 'Развлечения',
        'other': 'Други',
        'generatePassword': 'Генерирай',
        'passwordStrength': 'Сила на паролата',
        'strong': 'Силна',
        'vulnerable': 'Уязвима',
        'weak': 'Слаба',
        'breached': 'Компрометирана',
        'usePassword': 'Използвай парола',
        'passwordGenerator': 'Генератор на пароли',
        'adjustSettings': 'Настройте опциите за генериране',
        'length': 'Дължина',
        'uppercase': 'Главни букви (A-Z)',
        'lowercase': 'Малки букви (a-z)',
        'numbers': 'Цифри (0-9)',
        'symbols': 'Символи (!@#$...)',

        # Categories
        'uncategorized': 'Некатегоризирани',

        # Settings
        'settingsTitle': 'Настройки',
        'managePreferences': 'Управлявайте вашите AegisX предпочитания и данни',
        'import': 'Импорт',
        'export': 'Експорт',
        'preferences': 'Предпочитания',
        'security': 'Сигурност',
        'support': 'Поддръжка',
        'importPasswords': 'Импортирай пароли',
        'selectPasswordManager': 'Изберете вашия мениджър на пароли, за да импортирате паролите си в AegisX.',
        'exportPasswords': 'Експортирай пароли',
        'exportDescription': 'Експортирайте вашите пароли в различни формати за архивиране или миграция.',
        'preferencesTitle': 'Предпочитания',
        'customizeExperience': 'Персонализирайте вашето AegisX изживяване.',
        'securityTitle': 'Сигурност',
        'manageSecuritySettings': 'Управлявайте настройките за сигурност на вашето AegisX хранилище.',
        'twoFactorAuth': 'Двуфакторна автентикация',
        'add2FALayer': 'Добавете допълнителен слой на сигурност с 2FA.',
        'enable2FA': 'Активирай 2FA',
        'disable2FA': 'Деактивирай 2FA',
        'language': 'Език',
        'chooseLanguage': 'Изберете предпочитания език.',
        'theme': 'Тема',
        'chooseTheme': 'Изберете предпочитана цветова схема.',
        'autoLock': 'Автоматично заключване',
        'autoLockDescription': 'Автоматично заключване на AegisX след период на неактивност.',
        'lightMode': 'Светла',
        'darkMode': 'Тъмна',
        'systemMode': 'Системна',
        'brightAndClean': 'Ярка и чиста',
        'easyOnEyes': 'Лесна за очите',
        'matchDevice': 'Според устройството',
        'savePreferences': 'Запази предпочитания',
        'json': 'JSON',
        'csv': 'CSV',
        'pgpEncrypted': 'PGP криптиран',
        'structuredDataFormat': 'Структуриран формат на данни',
        'spreadsheetFormat': 'Формат на електронна таблица',
        'passwordProtected': 'Защитен с парола',
        'encryptionPassword': 'Парола за криптиране',
        'exportPGP': 'Експортирай PGP',
        'exportNote': 'JSON и CSV експортите съдържат некриптирани пароли. Съхранявайте ги сигурно. PGP експортът е криптиран с избраната от вас парола.',
        'note': 'Забележка',
        'securityDashboard': 'Табло за сигурност',
        'passwordBreached': 'Парола е компрометирана',
        'passwordBreachedDescription': 'Тази парола е била част от изтекли данни.',
        'passwordDuplicates': 'Дублирани пароли',
        'passwordDuplicatesDescription': 'Тези пароли се използват за множество акаунти.',
        'passwordWeak': 'Слаби пароли',
        'passwordWeakDescription': 'Тези пароли са твърде прости и лесни за отгатване.',
        'passwordVulnerable': 'Уязвими пароли',
        'passwordVulnerableDescription': 'Тези пароли биха могли да бъдат по-силни.',
        'strongPasswords': 'Силни пароли',
        'weakPasswords': 'Слаби пароли',
        'breachedPasswords': 'Компрометирани пароли',
        'duplicatePasswords': 'Дублирани пароли',
        'totalEntries': 'Общо записи',
        'analyze': 'Анализирай',
        'analyzing': 'Анализиране...',
        'securityScore': 'Резултат за сигурност',
        'good': 'Добър',
        'fair': 'Приемлив',
        'poor': 'Слаб',
        'unrated': 'Неоценен',
        'actionRequired': 'Изисква се действие',
        'viewAll': 'Виж всички',
        'noSecurityIssues': 'Не са открити проблеми със сигурността!',
        'allPasswordsSecure': 'Всичките ви пароли са сигурни.',
        'checkNow': 'Провери сега',
        'emailBreached': 'Имейлът е компрометиран',
        'emailBreachedDescription': 'Този имейл адрес е бил част от изтекли данни.'
    }
}

# ============================================================
#  DB auto-init
# ============================================================
# init_db() # Moved to main section after loading env variables
# migrate_db() # Moved to main section after loading env variables

# ============================================================
#  .env + Flask
# ============================================================
# Load environment variables from .env file
load_dotenv()
# Get Flask secret key from environment or generate a random one
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
# Get session timeout settings from environment or use defaults
SESSION_TIME = int(os.getenv("SESSION_TIME", 60))       # minutes (absolute session max)
INACTIVITY_SECONDS = int(os.getenv("INACTIVITY_SECONDS", 300))  # seconds (idle lock)

# Initialize encryption secret key on startup
init_secret_key()

# Initialize database and run migrations
init_db()
migrate_db()

# Create Flask application instance
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.permanent_session_lifetime = timedelta(minutes=SESSION_TIME)
# Set secure cookie options
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict"
)

# Initialize password hasher for master password
pass_hash = PasswordHasher()

# ============================================================
#  CSRF (single, consistent)
# ============================================================
@app.context_processor
def inject_csrf_and_translations():
    """Inject CSRF token and translation function into all templates"""
    return {
        "csrf_token": generate_csrf_token(session),
        "t": get_translation_function(session)
    }

@app.before_request
def csrf_guard_all_posts():
    """Guard all POST requests with CSRF token verification"""
    if request.method != "POST":
        return
    # Allow first setup without CSRF
    if request.endpoint in ("first",):
        return
    # Allow static files
    if request.endpoint and request.endpoint.startswith("static"):
        return

    # Verify CSRF token from form or header
    if not verify_csrf_token(request, session):
        return jsonify({"error": "Invalid or missing CSRF token"}), 400

@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 Bad Request errors with detailed logging"""
    print(f"[AegisX] ===== 400 BAD REQUEST ERROR =====")
    print(f"[AegisX] Error: {e}")
    print(f"[AegisX] Request URL: {request.url}")
    print(f"[AegisX] Request method: {request.method}")
    print(f"[AegisX] Request headers: {dict(request.headers)}")
    print(f"[AegisX] Request data: {request.data}")
    print(f"[AegisX] Request args: {request.args}")
    print(f"[AegisX] Request form: {request.form}")
    return jsonify({"error": "Bad Request", "details": str(e)}), 400

# ============================================================
#  Session auto-lock (idle + absolute)
# ============================================================
@app.before_request
def enforce_idle_and_session_timeout():
    """Enforce session timeout based on inactivity and absolute time limits"""
    enforce_session_timeout(session, SESSION_TIME, INACTIVITY_SECONDS)

# ============================================================
#  Clipboard auto-clear with Python
# ============================================================
# Track active clipboard clear timers
# clipboard_timers = {} # Moved to lib.clipboard_manager

# def clear_clipboard_after_delay(delay_seconds, clipboard_id=None): # Moved to lib.clipboard_manager
#     """
#     Clear clipboard after a delay using Python subprocess with xclip.
#     This runs in a background thread and clears system-wide clipboard on Linux X11.
#     """
#     def clear_task():
#         time_module.sleep(delay_seconds)
#         try:
#             current_clipboard_id = clipboard_id if clipboard_id is not None else f"{int(time.time())}_{secrets.token_hex(8)}"

#             try:
#                 import subprocess
#                 import platform

#                 if platform.system() == 'Linux':
#                     # Clear clipboard using xclip (X11)
#                     subprocess.run(['xclip', '-selection', 'clipboard'],
#                                  input=b'',
#                                  check=True,
#                                  timeout=2)
#                     print(f"[AegisX] ✓ Clipboard cleared after {delay_seconds} seconds using xclip")
#                 else:
#                     # Fallback to pyperclip for other platforms
#                     try:
#                         import pyperclip
#                         pyperclip.copy('')
#                         print(f"[AegisX] ✓ Clipboard cleared after {delay_seconds} seconds using pyperclip")
#                     except ImportError:
#                         print(f"[AegisX] pyperclip not installed, clipboard clear skipped")
#             except FileNotFoundError:
#                 print(f"[AegisX] xclip not installed. Install with: sudo apt-get install xclip")
#             except subprocess.TimeoutExpired:
#                 print(f"[AegisX] xclip timeout")
#             except Exception as e:
#                 print(f"[AegisX] Failed to clear clipboard: {e}")

#             # Remove from tracking
#             clipboard_timers.pop(current_clipboard_id, None)
#         except Exception as e:
#             print(f"[AegisX] Clipboard clear error: {e}")

#     # Start thread
#     thread = threading.Thread(target=clear_task, daemon=True)
#     if clipboard_id is None:
#         clipboard_id = f"{int(time.time())}_{secrets.token_hex(8)}"
#     clipboard_timers[clipboard_id] = thread
#     thread.start()
#     return clipboard_id

@app.route("/api/schedule-clipboard-clear", methods=["POST"])
def api_schedule_clipboard_clear():
    """Schedule clipboard clearing after password copy"""
    try:
        print(f"[AegisX] ===== CLIPBOARD CLEAR API CALLED =====")
        print(f"[AegisX] Request method: {request.method}")
        print(f"[AegisX] Content-Type: {request.content_type}")
        print(f"[AegisX] Raw data: {request.data}")
        print(f"[AegisX] Session keys: {list(session.keys())}")
        print(f"[AegisX] Session authorized: {'authorized' in session}")

        if "authorized" not in session:
            print(f"[AegisX] Clipboard clear request unauthorized")
            return jsonify({"error": "Unauthorized"}), 401

        try:
            data = request.get_json(force=True)
        except Exception as json_error:
            print(f"[AegisX] JSON parsing failed: {json_error}")
            return jsonify({"error": "Invalid JSON format"}), 400

        if not data:
            print(f"[AegisX] No JSON data received")
            return jsonify({"error": "No data provided"}), 400

        print(f"[AegisX] Parsed JSON data: {data}")

        timeout_seconds = data.get("timeout")
        print(f"[AegisX] Timeout value: {timeout_seconds}, type: {type(timeout_seconds)}")

        if timeout_seconds is None:
            print(f"[AegisX] No timeout in request")
            return jsonify({"error": "timeout field required"}), 400

        # Convert to integer
        try:
            timeout_seconds = int(timeout_seconds)
        except (ValueError, TypeError) as convert_error:
            print(f"[AegisX] Invalid timeout value: {timeout_seconds}, error: {convert_error}")
            return jsonify({"error": f"Invalid timeout value: {timeout_seconds}. Must be a positive integer."}), 400

        if timeout_seconds <= 0:
            print(f"[AegisX] Invalid timeout (must be positive): {timeout_seconds}")
            return jsonify({"error": "Timeout must be a positive integer"}), 400

        print(f"[AegisX] Scheduling clipboard clear in {timeout_seconds} seconds")

        # Call the moved function from clipboard_manager
        clipboard_id = clear_clipboard_after_delay(timeout_seconds)

        print(f"[AegisX] ✓ Clipboard clear scheduled successfully with ID: {clipboard_id}")
        return jsonify({"success": True, "message": f"Clipboard will clear in {timeout_seconds} seconds", "clipboard_id": clipboard_id}), 200

    except Exception as e:
        print(f"[AegisX] ✗ Exception in clipboard clear API: {e}")
        print(f"[AegisX] ✗ Exception type: {type(e)}")
        import traceback
        print(f"[AegisX] ✗ Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


# ============================================================
#  Routes
# ============================================================
@app.route("/")
def home():
    """Home page - redirect to login if master key exists, otherwise show first-time setup"""
    if os.path.exists("master_key.txt"):
        return redirect(url_for("login"))
    return render_template("first.html")

@app.route("/first/", methods=["GET", "POST"])
def first():
    """First-time setup page - create master password"""
    if request.method == "POST":
        master_password = request.form.get("master_password", "")
        if not master_password:
            return render_template("first.html", error="Password cannot be empty.")
        # Hash the master password using Argon2
        hashed = pass_hash.hash(master_password)
        # Save hashed password to file
        with open("master_key.txt", "w") as f:
            f.write(hashed)
        # Initialize encryption secret key
        init_secret_key()
        return redirect(url_for("login"))
    return render_template("first.html")

@app.route("/login/", methods=["GET", "POST"])
def login():
    """Login page - verify master password and optional 2FA code"""
    if not os.path.exists("master_key.txt"):
        return redirect(url_for("first"))

    if 'authorized' in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        entered = request.form.get("master_password", "")
        twofa_code = request.form.get("twofa_code", "")

        try:
            # Read stored master password hash
            with open("master_key.txt", "r") as f:
                stored = f.read()
            # Verify password using Argon2
            if pass_hash.verify(stored, entered):
                # Check if 2FA is enabled
                if check_2fa_enabled():
                    if not twofa_code:
                        return render_template("login.html", error="2FA code is required.")

                    # Verify 2FA code
                    if not verify_2fa_code(twofa_code):
                        return render_template("login.html", error="Invalid 2FA code.")

                # Login successful - create session
                session["authorized"] = True
                session["session_start"] = int(time.time())
                session["last_activity"] = int(time.time())
                # Set default auto_lock_timeout
                session['auto_lock_timeout'] = INACTIVITY_SECONDS
                # Set default trash_auto_delete_days to 30 days
                session['trash_auto_delete_days'] = 30
                # Set default clipboard_timeout to 30 seconds
                session['clipboard_timeout'] = 30

                # Auto-delete old trash items on login
                auto_delete_trash_on_login()

                return redirect(url_for("dashboard"))
            else:
                return render_template("login.html", error="Invalid master password.")
        except Exception as e:
            print(f"[AegisX] Login error: {e}")
            return render_template("login.html", error="Invalid master password.")
    return render_template("login.html")

@app.route("/check-2fa", methods=["POST"])
def check_2fa():
    """API endpoint to check if password is valid and if 2FA is enabled"""
    entered = request.form.get("master_password", "")

    try:
        with open("master_key.txt", "r") as f:
            stored = f.read()

        password_valid = pass_hash.verify(stored, entered)
        twofa_enabled = check_2fa_enabled()

        return {
            "password_valid": password_valid,
            "twofa_enabled": twofa_enabled
        }
    except Exception as e:
        print(f"[AegisX] Check 2FA error: {e}")
        return {"password_valid": False, "twofa_enabled": False}

@app.route("/settings/")
def settings():
    """Settings page - manage preferences, import/export, 2FA, etc."""
    if "authorized" not in session:
        return redirect(url_for("login"))

    # Check for success parameter from preferences save
    preferences_success = request.args.get("success") == "preferences"

    return render_template("settings.html", preferences_success=preferences_success)

@app.route("/settings/import/", methods=["POST"])
def import_passwords():
    """Import passwords from various password managers (JSON, CSV, or PGP encrypted)"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    try:
        # Check if file was uploaded
        if 'import_file' not in request.files:
            return render_template("settings.html", import_error="No file uploaded")

        file = request.files['import_file']
        manager_type = request.form.get('manager_type', 'generic')
        # Get the password for PGP decryption if provided
        decryption_password = request.form.get('decryption_password', '')

        # Call the imported function from lib/import_export.py
        success, count, error = import_passwords_from_file(file, manager_type, encrypt_data, decryption_password if decryption_password else None)

        if success:
            return render_template("settings.html", import_success=True, import_count=count)
        else:
            return render_template("settings.html", import_error=error)

    except Exception as e:
        print(f"[AegisX] Import error: {e}")
        return render_template("settings.html", import_error=f"Import failed: {str(e)}")

@app.route("/settings/export/<format>", methods=["POST"], endpoint="export_passwords")
def export_passwords_route(format):
    """Export passwords in the specified format (json, csv, or pgp)"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    try:
        # Get encryption password if provided (for PGP export)
        encryption_password = request.form.get('encryption_password', '')

        # Get all non-deleted passwords
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM passwords WHERE is_deleted=0")
        ids = [row[0] for row in cur.fetchall()]
        conn.close()

        if not ids:
            return render_template("settings.html", export_error="No passwords to export")

        # Call the export function from lib/import_export.py
        success, response_data, content_type, filename, error = export_passwords(
            ids, format, decrypt_data, encryption_password if encryption_password else None
        )

        if not success:
            return render_template("settings.html", export_error=error)

        # Return the file for download
        response = make_response(response_data)
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = content_type
        return response

    except Exception as e:
        print(f"[AegisX] Export error: {e}")
        return render_template("settings.html", export_error=f"Export failed: {str(e)}")

@app.route("/settings/preferences/", methods=["POST"])
def save_preferences():
    """Save user preferences (auto-lock timeout, theme, language, trash auto-delete, clipboard timeout)"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    try:
        auto_lock_timeout_str = request.form.get('auto_lock_timeout', '300')
        theme = request.form.get('theme', 'dark')
        language = request.form.get('language', 'en')
        trash_auto_delete_days_str = request.form.get('trash_auto_delete_days', '30')
        clipboard_timeout_str = request.form.get('clipboard_timeout', '30')

        # Validate and sanitize auto_lock_timeout
        valid_timeouts = {
            "60": 60, "300": 300, "600": 600,
            "900": 900, "1800": 1800, "3600": 3600,
            "0": 0  # Allow 0 for disabling auto-lock
        }
        auto_lock_timeout = valid_timeouts.get(auto_lock_timeout_str, 300)

        # Validate trash auto-delete days
        try:
            trash_auto_delete_days = max(0, int(trash_auto_delete_days_str))
        except ValueError:
            trash_auto_delete_days = 30

        try:
            clipboard_timeout = max(0, int(clipboard_timeout_str))
        except ValueError:
            clipboard_timeout = 30

        # Validate theme
        valid_themes = ['light', 'dark', 'system']
        if theme not in valid_themes:
            theme = 'dark'

        # Validate language
        valid_languages = ['en', 'bg']
        if language not in valid_languages:
            language = 'en'

        # Update session with preferences
        session['auto_lock_timeout'] = auto_lock_timeout
        session['theme'] = theme
        session['language'] = language
        session['trash_auto_delete_days'] = trash_auto_delete_days
        session['clipboard_timeout'] = clipboard_timeout

        return redirect(url_for("settings") + "?success=preferences")

    except Exception as e:
        print(f"[AegisX] Preferences save error: {e}")
        return render_template("settings.html", pref_error=f"Failed to save preferences: {str(e)}")

@app.route("/dashboard/")
def dashboard():
    """Main dashboard - display all passwords with search and filtering"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    selected_id = request.args.get("selected", type=int)
    selected_category = request.args.get("category", "All")
    search_query = request.args.get("search", "").strip()
    tab = request.args.get("tab", "passwords")

    if tab == "passkeys":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, title, username, credential_id, url, category, first_created, last_modified, is_favorite FROM passkey_credentials WHERE is_deleted=0")
        rows = cur.fetchall()
        conn.close()

        entries = []
        for row in rows:
            entries.append({
                "id": row[0],
                "title": decrypt_data(row[1]) if row[1] else "Untitled",
                "username": decrypt_data(row[2]) if row[2] else "",
                "credential_id": row[3],
                "url": decrypt_data(row[4]) if row[4] else "",
                "category": row[5] if row[5] else "Uncategorized",
                "first_created": row[6],
                "last_modified": row[7],
                "is_favorite": row[8] if row[8] else 0,
                "type": "passkey"  # Mark as passkey type
            })

        selected_entry = next((e for e in entries if e["id"] == selected_id), None)
        categories = sorted(set(e.get("category", "Uncategorized") for e in entries))

        current_lang = session.get('language', 'en')
        translations = TRANSLATIONS.get(current_lang, TRANSLATIONS['en'])

        return render_template("dashboard.html", data=entries, selected_entry=selected_entry,
                             categories=categories, selected_category=selected_category,
                             search_query=search_query, translations=translations,
                             current_tab=tab)

    # Fetch all passwords (excluding deleted ones)
    entries = fetch_all_passwords(decrypt_data)
    entries = [e for e in entries if not e.get("is_deleted", 0)]

    # Apply search filter if query provided
    if search_query:
        entries = fuzzy_search_passwords(entries, search_query)

    # Filter by category if not "All"
    if selected_category != "All":
        entries = [e for e in entries if e.get("category", "Uncategorized") == selected_category]

    # Get unique categories for the sidebar
    all_entries = fetch_all_passwords(decrypt_data)
    all_entries = [e for e in all_entries if not e.get("is_deleted", 0)]
    categories = sorted(set(e.get("category", "Uncategorized") for e in all_entries))

    # Get selected entry details if ID provided
    selected_entry = next((e for e in entries if e["id"] == selected_id), None)

    # Get translations for current language
    current_lang = session.get('language', 'en')
    translations = TRANSLATIONS.get(current_lang, TRANSLATIONS['en'])

    return render_template("dashboard.html", data=entries, selected_entry=selected_entry,
                         categories=categories, selected_category=selected_category,
                         search_query=search_query, translations=translations,
                         current_tab=tab)

@app.route("/dashboard/add/", methods=["GET", "POST"])
def add():
    """Add a new password entry"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        conn = None
        try:
            title = request.form.get("title", "").strip()
            url = request.form.get("url", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            totp_secret = request.form.get("totp_secret", "").strip()
            category = request.form.get("category", "Uncategorized").strip()

            print(f"[AegisX] Adding new password:")
            print(f"[AegisX]   title: {title}")
            print(f"[AegisX]   url: {url}")
            print(f"[AegisX]   username: {username}")
            print(f"[AegisX]   password: {'*' * len(password)}")
            print(f"[AegisX]   totp_secret: {totp_secret}")
            print(f"[AegisX]   category: {category}")

            if not username or not password:
                return jsonify({"error": "Username and password are required"}), 400

            encrypted_title = encrypt_data(title or "Untitled")
            encrypted_username = encrypt_data(username)
            encrypted_password = encrypt_data(password)
            encrypted_url = encrypt_data(url) if url else None
            encrypted_totp = encrypt_data(totp_secret) if totp_secret else None

            print(f"[AegisX] Encrypted data lengths:")
            print(f"[AegisX]   title: {len(encrypted_title) if encrypted_title else 0}")
            print(f"[AegisX]   username: {len(encrypted_username) if encrypted_username else 0}")
            print(f"[AegisX]   password: {len(encrypted_password) if encrypted_password else 0}")
            print(f"[AegisX]   url: {len(encrypted_url) if encrypted_url else 0}")
            print(f"[AegisX]   totp: {len(encrypted_totp) if encrypted_totp else 0}")


            # Insert encrypted password entry into database
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO passwords (title, username, password, url, totp_secret, category, first_created, last_modified) VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'), datetime('now','localtime'))",
                (encrypted_title, encrypted_username, encrypted_password, encrypted_url, encrypted_totp, category)
            )
            conn.commit()
            print(f"[AegisX] Successfully inserted password with ID: {cur.lastrowid}")
            return redirect(url_for("dashboard"))
        except sqlite3.OperationalError as e:
            print(f"[AegisX] Database error adding entry: {e}")
            return jsonify({"error": f"Database error: {str(e)}. Please try again."}), 500
        except Exception as e:
            print(f"[AegisX] Error adding entry: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"Failed to add entry: {str(e)}"}), 500
        finally:
            if conn:
                conn.close()

    return render_template("add.html")

@app.route("/dashboard/edit/<int:id_num>/", methods=["GET", "POST"])
def edit(id_num):
    """Edit an existing password entry"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "POST":
            title = request.form.get("title", "")
            url = request.form.get("url", "")
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            totp_secret = request.form.get("totp_secret", "")
            category = request.form.get("category", "Uncategorized")

            # Get old password for history tracking
            cur.execute("SELECT password FROM passwords WHERE id=?", (id_num,))
            old_row = cur.fetchone()
            if old_row:
                old_password = old_row[0]
                # Only save to history if password actually changed
                if old_password != encrypt_data(password):
                    cur.execute(
                        "INSERT INTO password_history (password_id, old_password, changed_at) VALUES (?, ?, datetime('now','localtime'))",
                        (id_num, old_password)
                    )

            # Update password entry with encrypted data
            cur.execute(
                "UPDATE passwords SET title=?, username=?, password=?, url=?, totp_secret=?, category=?, last_modified=datetime('now','localtime') WHERE id=?",
                (encrypt_data(title or "Untitled"), encrypt_data(username), encrypt_data(password), encrypt_data(url), encrypt_data(totp_secret) if totp_secret else None, category, id_num)
            )
            conn.commit()
            return redirect(url_for("dashboard"))

        # GET request - fetch entry for editing
        cur.execute("SELECT * FROM passwords WHERE id=?", (id_num,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Entry not found"}), 404

        # Decrypt entry data for display
        entry = {
            "id": row[0],
            "title": decrypt_data(row[1]) if row[1] else "",
            "username": decrypt_data(row[2]) if row[2] else "",
            "password": decrypt_data(row[3]),
            "url": decrypt_data(row[4]) if row[4] else "",
            "totp_secret": decrypt_data(row[5]) if row[5] else "",
            "category": row[8] if len(row) > 8 else "Uncategorized",
        }
        return render_template("edit.html", entry=entry)
    except sqlite3.OperationalError as e:
        print(f"[AegisX] Database error editing entry: {e}")
        return jsonify({"error": f"Database error: {str(e)}. Please try again."}), 500
    except Exception as e:
        print(f"[AegisX] Error editing entry: {e}")
        return jsonify({"error": f"Failed to edit entry: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route("/dashboard/delete/<int:id_num>/", methods=["POST"])
def delete(id_num):
    """Soft delete a password entry (move to trash)"""
    if "authorized" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor()
    # Mark as deleted instead of removing from database
    cur.execute("UPDATE passwords SET is_deleted=1, deleted_at=datetime('now','localtime') WHERE id=?", (id_num,))
    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/dashboard/bulk-delete", methods=["POST"])
def bulk_delete():
    """Bulk soft delete multiple password entries (move to trash)"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        data = request.get_json()
        ids = data.get("ids", [])

        if not ids or not isinstance(ids, list):
            return {"error": "Invalid request"}, 400

        conn = get_db_connection()
        cur = conn.cursor()

        # Mark all selected entries as deleted
        placeholders = ','.join('?' * len(ids))
        cur.execute(f"UPDATE passwords SET is_deleted=1, deleted_at=datetime('now','localtime') WHERE id IN ({placeholders})", ids)

        conn.commit()
        conn.close()

        return {"success": True, "deleted": len(ids)}
    except Exception as e:
        print(f"[AegisX] Bulk delete error: {e}")
        return {"error": "Failed to delete passwords"}, 500

@app.route("/dashboard/bulk-export", methods=["POST"])
def bulk_export():
    """Bulk export selected password entries"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        data = request.get_json()
        ids = data.get("ids", [])
        export_format = data.get("format", "json")
        encryption_password = data.get("encryption_password", "")

        # Call export function from lib/import_export.py
        success, response_data, content_type, filename, error = export_passwords(
            ids, export_format, decrypt_data, encryption_password if encryption_password else None
        )

        if not success:
            return {"error": error}, 400

        # Return file for download
        response = make_response(response_data)
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = content_type
        return response

    except Exception as e:
        print(f"[AegisX] Bulk export error: {e}")
        return {"error": "Failed to export passwords"}, 500

@app.route("/settings/2fa/status", methods=["GET"])
def twofa_status():
    """Check if 2FA is enabled for the account"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    enabled = check_2fa_enabled()
    return {"enabled": enabled}

@app.route("/settings/2fa/enable", methods=["POST"])
def twofa_enable_route():
    """Generate 2FA secret and QR code for setup"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    # Generate a new TOTP secret and QR code
    secret, qr_code = generate_2fa_qr()

    # Store temporarily in session until verified
    session["pending_2fa_secret"] = secret

    return {
        "success": True,
        "secret": secret,
        "qr_code": qr_code
    }

@app.route("/settings/2fa/verify", methods=["POST"])
def twofa_verify():
    """Verify 2FA code and enable 2FA if valid"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    data = request.get_json()
    code = data.get("code", "")
    secret = session.get("pending_2fa_secret")

    if not secret:
        return {"success": False, "error": "No pending 2FA setup"}

    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=1):
        enable_2fa(secret)
        session.pop("pending_2fa_secret", None)
        return {"success": True}
    else:
        return {"success": False, "error": "Invalid code"}

@app.route("/settings/2fa/disable", methods=["POST"])
def twofa_disable_route():
    """Disable 2FA for the account"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    # Remove 2FA secret file
    disable_2fa()
    return {"success": True}

@app.route("/logout/")
def logout():
    """Log out and clear session"""
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard/trash/")
def trash():
    """Display trash page with deleted items"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    # Fetch all deleted items
    trash_items = get_all_trash_items(decrypt_data)

    # Get translations for current language
    current_lang = session.get('language', 'en')
    translations = TRANSLATIONS.get(current_lang, TRANSLATIONS['en'])

    return render_template("trash.html", trash_items=trash_items, translations=translations)

@app.route("/sentinel/")
def sentinel():
    """Display Sentinel security dashboard page"""
    if "authorized" not in session:
        return redirect(url_for("login"))

    # Get translations for current language
    current_lang = session.get('language', 'en')
    translations = TRANSLATIONS.get(current_lang, TRANSLATIONS['en'])

    return render_template("sentinel.html", translations=translations)

@app.route("/api/trash/<int:id_num>")
def get_trash_item(id_num):
    """API endpoint to get a single trash item details"""
    if "authorized" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Fetch trash item by ID
    item = get_trash_item_by_id(id_num, decrypt_data)

    if item:
        return jsonify(item)
    else:
        return jsonify({"error": "Item not found"}), 404

@app.route("/dashboard/trash/restore/<int:id_num>/", methods=["POST"])
def restore_from_trash_route(id_num):
    """Restore an item from trash"""
    if "authorized" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    success = restore_from_trash(id_num)

    if success:
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Failed to restore item"}), 500

@app.route("/dashboard/trash/delete-permanent/<int:id_num>/", methods=["POST"])
def delete_permanent_route(id_num):
    """Permanently delete an item from trash"""
    if "authorized" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    success = delete_permanent(id_num)

    if success:
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Failed to delete item"}), 500

@app.route("/dashboard/trash/empty/", methods=["POST"])
def empty_trash_route():
    """Empty all items from trash"""
    if "authorized" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    deleted_count = empty_trash()

    return jsonify({"success": True, "deleted_count": deleted_count})

# ============================================================
#  Password strength API route
# ============================================================
@app.route("/api/check-password-strength", methods=["POST"])
def api_check_password_strength():
    """API endpoint to check password strength (weak, vulnerable, strong, breached)"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    data = request.get_json()
    password = data.get("password", "")

    # Check strength using imported function
    strength = check_password_strength(password, check_password_breach)

    return {
        "strength": strength
    }

@app.route("/api/security-dashboard", methods=["GET"])
def api_security_dashboard():
    """API endpoint to get security analysis of all passwords"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        print("[AegisX] Starting security analysis...")
        # Analyze all passwords using imported function
        stats = analyze_password_security(decrypt_data, check_password_strength, check_password_breach, check_email_breach)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, title, username, url FROM passwords WHERE is_deleted=0")
        rows = cur.fetchall()
        conn.close()

        all_passwords = []
        for row in rows:
            all_passwords.append({
                "id": row[0],
                "title": decrypt_data(row[1]) if row[1] else "Untitled",
                "username": decrypt_data(row[2]) if row[2] else "",
                "url": decrypt_data(row[3]) if row[3] else ""
            })

        hibp_breaches = []
        if stats.get('breached_emails_list'):
            for email_data in stats['breached_emails_list']:
                # Fetch full breach details for each breach name
                for breach_name in email_data.get('breaches', []):
                    hibp_breaches.append({
                        'Name': breach_name,
                        'Email': email_data.get('email', ''),
                        'BreachDate': 'Unknown'  # HIBP API doesn't provide date in truncated response
                    })

        stats['all_passwords'] = all_passwords
        stats['hibp_breaches'] = hibp_breaches

        print(f"[AegisX] Analysis complete. Weak: {len(stats['weak_passwords'])}, Breached: {len(stats['breached_passwords'])}, Duplicates: {len(stats['duplicate_passwords'])}, HIBP: {len(hibp_breaches)}")
        return stats
    except Exception as e:
        print(f"[AegisX] Security dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return {"error": f"Failed to analyze passwords: {str(e)}"}, 500

# ============================================================
#  Search API route
# ============================================================
@app.route("/api/search", methods=["POST"])
def api_search():
    """API endpoint for searching passwords using fuzzy search"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    data = request.get_json()
    query = data.get("query", "").strip()

    # Fetch all passwords
    entries = fetch_all_passwords(decrypt_data)

    # Apply fuzzy search if query provided
    if query:
        entries = fuzzy_search_passwords(entries, query)

    # Return simplified data for frontend
    results = []
    for entry in entries:
        results.append({
            "id": entry["id"],
            "title": entry.get("title", ""),
            "username": entry.get("username", ""),
            "url": entry.get("url", ""),
            "category": entry.get("category", "Uncategorized"),
            "is_favorite": entry.get("is_favorite", 0)
        })

    return {"success": True, "results": results}

# ============================================================
#  Toggle favorite status
# ============================================================
@app.route("/dashboard/toggle-favorite/<int:id_num>", methods=["POST"])
def toggle_favorite(id_num):
    """Toggle favorite status of a password entry"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get current favorite status
        cur.execute("SELECT is_favorite FROM passwords WHERE id=?", (id_num,))
        row = cur.fetchone()

        if not row:
            return {"error": "Entry not found"}, 404

        # Toggle favorite status (0 to 1 or 1 to 0)
        new_status = 0 if row[0] == 1 else 1
        cur.execute("UPDATE passwords SET is_favorite=? WHERE id=?", (new_status, id_num))

        conn.commit()
        conn.close()

        return {"success": True, "is_favorite": new_status}
    except Exception as e:
        print(f"[AegisX] Toggle favorite error: {e}")
        return {"error": "Failed to toggle favorite"}, 500

# ============================================================
#  Password history API route
# ============================================================
@app.route("/api/password-history/<int:id_num>", methods=["GET"])
def get_password_history(id_num):
    """API endpoint to get password change history for an entry"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch password history for this entry (last 10 changes)
        cur.execute(
            "SELECT old_password, changed_at FROM password_history WHERE password_id=? ORDER BY changed_at DESC LIMIT 10",
            (id_num,)
        )
        rows = cur.fetchall()
        conn.close()

        # Decrypt passwords in history
        history = []
        for row in rows:
            history.append({
                "password": decrypt_data(row[0]),
                "changed_at": row[1]
            })

        return {"success": True, "history": history}
    except Exception as e:
        print(f"[AegisX] Password history error: {e}")
        return {"error": "Failed to fetch password history"}, 500

@app.route("/api/filter-passwords", methods=["POST"])
def api_filter_passwords():
    """API endpoint to filter passwords by security criteria (weak, breached, duplicates)"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        data = request.get_json()
        filter_type = data.get("filter_type", "all")

        print(f"[AegisX] Filtering passwords by: {filter_type}")

        # Analyze passwords using imported function
        stats = analyze_password_security(decrypt_data, check_password_strength, check_password_breach, check_email_breach)

        filtered_ids = []

        # Filter based on type
        if filter_type == "weak":
            filtered_ids = [pwd['id'] for pwd in stats['weak_passwords']]
            print(f"[AegisX] Weak password IDs: {filtered_ids}")
        elif filter_type == "breached":
            filtered_ids = [pwd['id'] for pwd in stats['breached_passwords']]
            print(f"[AegisX] Breached password IDs: {filtered_ids}")
        elif filter_type == "duplicates":
            filtered_ids = [pwd['id'] for pwd in stats['duplicate_passwords']]
            print(f"[AegisX] Duplicate password IDs: {filtered_ids}")

        return {"success": True, "ids": filtered_ids}
    except Exception as e:
        print(f"[AegisX] Filter passwords error: {e}")
        import traceback
        traceback.print_exc()
        return {"error": "Failed to filter passwords"}, 500

@app.route("/api/entry/<int:id_num>", methods=["GET"])
def api_get_entry(id_num):
    """API endpoint to get full entry details for display in detail panel"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch entry from database
        cur.execute("SELECT * FROM passwords WHERE id=?", (id_num,))
        row = cur.fetchone()
        conn.close()

        if not row:
            print(f"[AegisX] Entry {id_num} not found")
            return {"error": "Entry not found"}, 404

        # Decrypt entry data
        try:
            print(f"[AegisX] Decrypting entry {id_num}...")
            decrypted_title = decrypt_data(row[1]) if row[1] else "Untitled"
            decrypted_username = decrypt_data(row[2]) if row[2] else ""
            decrypted_password = decrypt_data(row[3])
            decrypted_url = decrypt_data(row[4]) if row[4] else ""
            decrypted_totp = decrypt_data(row[5]) if row[5] else ""
            print(f"[AegisX] Decryption successful for entry {id_num}")
        except Exception as decrypt_error:
            print(f"[AegisX] Decryption error for entry {id_num}: {decrypt_error}")
            raise decrypt_error

        # Fetch password history for this entry
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT old_password, changed_at FROM password_history WHERE password_id=? ORDER BY changed_at DESC LIMIT 10",
            (id_num,)
        )
        history_rows = cur.fetchall()
        conn.close()

        # Decrypt password history
        history = []
        for hist_row in history_rows:
            try:
                history.append({
                    "password": decrypt_data(hist_row[0]),
                    "changed_at": hist_row[1]
                })
            except Exception:
                print(f"[AegisX] History decryption error for entry {id_num}. Skipping.")
                continue

        last_modified, first_created = format_entry_dates(row[6] if row[6] else None, row[7] if row[7] else None)

        # Build entry response
        entry = {
            "id": row[0],
            "title": decrypted_title,
            "username": decrypted_username,
            "password": decrypted_password,
            "url": decrypted_url,
            "totp_secret": decrypted_totp,
            "last_modified": last_modified,
            "first_created": first_created,
            "is_favorite": row[8] if len(row) > 8 else 0,
            "category": row[9] if len(row) > 9 else "Uncategorized",
            "history": history
        }

        print(f"[AegisX] Successfully retrieved entry {id_num}")
        return entry
    except Exception as e:
        print(f"[AegisX] API entry fetch error for {id_num}: {e}")
        import traceback
        traceback.print_exc()
        return {"error": f"Failed to fetch entry: {str(e)}"}, 500

# ============================================================
#  Passkey detection API endpoints
# ============================================================

@app.route("/api/check-passkey-support", methods=["POST"])
def api_check_passkey_support():
    """Check if a website supports passkeys based on domain"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        data = request.get_json()
        url = data.get("url", "")
        password_id = data.get("password_id")

        if not url:
            return {"supports_passkey": False, "checked": False}

        # Extract domain from URL
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
        domain = parsed.netloc or parsed.path

        # Known passkey-enabled domains (this list should be expanded)
        passkey_domains = {
            'google.com', 'accounts.google.com',
            'microsoft.com', 'login.microsoft.com',
            'apple.com', 'appleid.apple.com',
            'github.com',
            'amazon.com',
            'paypal.com',
            'ebay.com',
            'facebook.com',
            'twitter.com', 'x.com',
            'linkedin.com',
            'shopify.com',
            'dropbox.com',
            'adobe.com',
            'bestbuy.com',
            'target.com',
            'walmart.com',
            'homedepot.com',
            'kayak.com',
            'booking.com',
            'airbnb.com'
        }

        # Check if domain supports passkeys
        supports_passkey = any(known_domain in domain.lower() for known_domain in passkey_domains)

        # Update database if password_id provided
        if password_id:
            conn = get_db_connection()
            cur = conn.cursor()

            # Check if record exists
            cur.execute("SELECT id FROM passkeys WHERE password_id=?", (password_id,))
            existing = cur.fetchone()

            if existing:
                cur.execute(
                    "UPDATE passkeys SET passkey_available=?, last_checked=datetime('now','localtime') WHERE password_id=?",
                    (1 if supports_passkey else 0, password_id)
                )
            else:
                cur.execute(
                    "INSERT INTO passkeys (password_id, passkey_available, last_checked) VALUES (?, ?, datetime('now','localtime'))",
                    (password_id, 1 if supports_passkey else 0)
                )

            conn.commit()
            conn.close()

        return {
            "supports_passkey": supports_passkey,
            "checked": True,
            "domain": domain
        }

    except Exception as e:
        print(f"[AegisX] Passkey check error: {e}")
        return {"error": str(e)}, 500

@app.route("/api/mark-passkey-converted/<int:id_num>", methods=["POST"])
def api_mark_passkey_converted(id_num):
    """Mark a password entry as converted to passkey"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if passkey record exists
        cur.execute("SELECT id FROM passkeys WHERE password_id=?", (id_num,))
        existing = cur.fetchone()

        if existing:
            cur.execute(
                "UPDATE passkeys SET has_passkey=1 WHERE password_id=?",
                (id_num,)
            )
        else:
            cur.execute(
                "INSERT INTO passkeys (password_id, has_passkey) VALUES (?, 1)",
                (id_num,)
            )

        conn.commit()
        conn.close()

        return {"success": True}

    except Exception as e:
        print(f"[AegisX] Mark passkey error: {e}")
        return {"error": str(e)}, 500

@app.route("/api/passkey-opportunities", methods=["GET"])
def api_passkey_opportunities():
    """Get list of passwords that support passkeys but haven\'t been converted"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        opportunities = get_passkey_opportunities(decrypt_data)

        return {"success": True, "opportunities": opportunities, "count": len(opportunities)}

    except Exception as e:
        print(f"[AegisX] Passkey opportunities error: {e}")
        return {"error": str(e)}, 500

@app.route("/api/trash/<int:id_num>", methods=["GET"])
def api_get_trash_entry(id_num):
    """API endpoint to get full trash entry details for display in detail panel"""
    if "authorized" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch deleted entry from database
        cur.execute("SELECT id, title, username, url, deleted_at, category, password FROM passwords WHERE id=? AND is_deleted=1", (id_num,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "Entry not found"}), 404

        # Decrypt fields for display
        return jsonify({
            "id": row[0],
            "title": decrypt_data(row[1]) if row[1] else "Untitled Entry",
            "username": decrypt_data(row[2]) if row[2] else "No username",
            "url": decrypt_data(row[3]) if row[3] else "No URL",
            "deleted_at": row[4] if row[4] else "N/A",
            "category": row[5] if row[5] else "Uncategorized",
            "password": decrypt_data(row[6]) if row[6] else ""
        })
    except Exception as e:
        print(f"[AegisX] Error fetching trash entry: {e}")
        return jsonify({"error": "Failed to fetch entry"}), 500

@app.route("/api/passkey/add", methods=["POST"])
def api_add_passkey():
    """Add a new passkey credential"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        data = request.get_json()
        title = data.get("title", "").strip()
        username = data.get("username", "").strip()
        credential_id = data.get("credential_id", "").strip()
        public_key = data.get("public_key", "")
        url = data.get("url", "").strip()
        category = data.get("category", "Uncategorized").strip()

        if not title or not credential_id:
            return {"error": "Title and credential ID are required"}, 400

        encrypted_title = encrypt_data(title)
        encrypted_username = encrypt_data(username) if username else None
        encrypted_url = encrypt_data(url) if url else None

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO passkey_credentials
               (title, username, credential_id, public_key, url, category, first_created, last_modified)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'), datetime('now','localtime'))""",
            (encrypted_title, encrypted_username, credential_id, public_key, encrypted_url, category)
        )
        conn.commit()
        passkey_id = cur.lastrowid
        conn.close()

        return {"success": True, "id": passkey_id}

    except Exception as e:
        print(f"[AegisX] Add passkey error: {e}")
        return {"error": str(e)}, 500

@app.route("/api/passkey/<int:id_num>", methods=["GET"])
def api_get_passkey(id_num):
    """Get passkey credential details"""
    if "authorized" not in session:
        return {"error": "Unauthorized"}, 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM passkey_credentials WHERE id=? AND is_deleted=0", (id_num,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return {"error": "Passkey not found"}, 404

        return {
            "id": row[0],
            "title": decrypt_data(row[1]) if row[1] else "Untitled",
            "username": decrypt_data(row[2]) if row[2] else "",
            "credential_id": row[3],
            "public_key": row[4],
            "url": decrypt_data(row[5]) if row[5] else "",
            "category": row[6] if row[6] else "Uncategorized",
            "first_created": row[7],
            "last_modified": row[8],
            "is_favorite": row[9] if row[9] else 0,
            "type": "passkey"
        }

    except Exception as e:
        print(f"[AegisX] Get passkey error: {e}")
        return {"error": str(e)}, 500

# ============================================================
#  Run
if __name__ == "__main__":
    # Run Flask app with SSL on localhost:8080
    app.run(host="localhost", port=8080, ssl_context=("cert.pem", "key.pem"), debug=True)
