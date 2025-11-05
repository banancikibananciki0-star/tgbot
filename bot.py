import json
import sqlite3
import subprocess
import hashlib
import logging
import uuid
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import config

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Глобальная переменная для авторизованных пользователей
AUTHORIZED_USERS = set()

# ===== БАЗА ДАННЫХ =====
def init_db():
    """Инициализация базы данных"""
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            traffic_limit INTEGER DEFAULT 1073741824,
            used_traffic INTEGER DEFAULT 0,
            port INTEGER,
            protocol TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bot_auth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Устанавливаем дефолтный пароль если его нет
    cursor.execute("SELECT COUNT(*) FROM bot_auth")
    if cursor.fetchone()[0] == 0:
        default_hash = hashlib.sha256(config.ADMIN_PASSWORD.encode()).hexdigest()
        cursor.execute("INSERT INTO bot_auth (password_hash) VALUES (?)", (default_hash,))
    
    conn.commit()
    conn.close()

def check_password(password):
    """Проверка пароля"""
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT password_hash FROM bot_auth ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result and result[0] == password_hash

def change_password(new_password):
    """Смена пароля"""
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    new_hash = hashlib.sha256(new_password.encode()).hexdigest()
    cursor.execute("INSERT INTO bot_auth (password_hash) VALUES (?)", (new_hash,))
    conn.commit()
    conn.close()

# ===== СИСТЕМА АВТОРИЗАЦИИ =====
async def authenticate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Авторизация по паролю в /start"""
    if len(context.args) != 1:
        await update.message.reply_text("🔐 Введите пароль для доступа:\n/start <пароль>")
        return False
    
    password = context.args[0]
    if not check_password(password):
        await update.message.reply_text("❌ Неверный пароль!")
        return False
    
    # Сохраняем авторизованного пользователя
    user_id = update.message.from_user.id
    AUTHORIZED_USERS.add(user_id)
    await update.message.reply_text(
        "✅ Авторизация успешна!\n\n"
        "Доступные команды:\n"
        "/add_vmess email [порт] - Добавить пользователя\n"
        "/list_users - Список пользователей\n" 
        "/change_password новый_пароль - Сменить пароль\n"
        "/restart_xray - Перезапустить Xray"
    )
    return True

def require_auth(func):
    """Декоратор для проверки авторизации"""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.message.from_user.id
        if user_id not in AUTHORIZED_USERS:
            await update.message.reply_text(
                "❌ Требуется авторизация!\n"
                "Используйте: /start <пароль>"
            )
            return
        return await func(update, context)
    return wrapper

# ===== РАБОТА С XRAY =====
def generate_uuid():
    """Генерация UUID для клиента"""
    return str(uuid.uuid4())

def create_vmess_config(email, port):
    """Создание конфигурации VMESS"""
    client_id = generate_uuid()
    
    inbound_config = {
        "port": int(port),
        "listen": "0.0.0.0",
        "protocol": "vmess",
        "settings": {
            "clients": [
                {
                    "id": client_id,
                    "email": email,
                    "level": 0,
                    "alterId": 0
                }
            ],
            "disableInsecureEncryption": False
        },
        "streamSettings": {
            "network": "tcp",
            "security": "none",
            "tcpSettings": {
                "header": {
                    "type": "none"
                }
            }
        },
        "tag": f"vmess-inbound-{port}"
    }
    
    return inbound_config, client_id

def modify_xray_config(email, port=None, protocol="vmess"):
    """Добавление нового inbound в конфиг Xray"""
    if port is None:
        port = config.DEFAULT_PORT
    
    # Читаем текущий конфиг
    try:
        with open(config.XRAY_CONFIG_PATH, 'r') as f:
            config_data = json.load(f)
    except FileNotFoundError:
        config_data = {"inbounds": [], "outbounds": []}
    
    # Создаем новый inbound
    if protocol.lower() == "vmess":
        new_inbound, client_id = create_vmess_config(email, port)
    else:
        raise ValueError(f"Протокол {protocol} пока не поддерживается")
    
    # Добавляем inbound в конфиг
    if 'inbounds' not in config_data:
        config_data['inbounds'] = []
    config_data['inbounds'].append(new_inbound)
    
    # Сохраняем конфиг
    with open(config.XRAY_CONFIG_PATH, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    return client_id, port

def restart_xray():
    """Перезагрузка Xray"""
    try:
        result = subprocess.run(
            ["systemctl", "restart", "xray"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        return True, "Xray успешно перезапущен"
    except subprocess.CalledProcessError as e:
        return False, f"Ошибка перезагрузки Xray: {e.stderr}"

def save_user_to_db(email, port, protocol):
    """Сохранение пользователя в БД"""
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO users (email, port, protocol) VALUES (?, ?, ?)",
        (email, port, protocol)
    )
    conn.commit()
    conn.close()

# ===== КОМАНДЫ БОТА =====
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /start с авторизацией"""
    if context.args:
        await authenticate(update, context)
    else:
        await update.message.reply_text(
            "🔐 Для доступа к боту требуется авторизация:\n"
            "/start <пароль>\n\n"
            f"💡 Дефолтный пароль: {config.ADMIN_PASSWORD}"
        )

@require_auth
async def add_vmess(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Добавление VMESS пользователя (БЕЗ ПАРОЛЯ В КОМАНДЕ!)"""
    if len(context.args) < 1:
        await update.message.reply_text("❌ Использование: /add_vmess <email> [порт]")
        return
    
    email = context.args[0]
    port = context.args[1] if len(context.args) > 1 else None
    
    try:
        if port:
            port = int(port)
            if port < 1 or port > 65535:
                await update.message.reply_text("❌ Порт должен быть от 1 до 65535")
                return
        
        # Создаем конфиг
        client_id, used_port = modify_xray_config(email, port, "vmess")
        
        # Перезагружаем Xray
        success, message = restart_xray()
        
        if success:
            save_user_to_db(email, used_port, "vmess")
            
            # Формируем данные для подключения
            server_ip = subprocess.getoutput("curl -s ifconfig.me")
            
            response = (
                f"✅ VMESS пользователь добавлен!\n\n"
                f"📧 Email: {email}\n"
                f"🔗 Порт: {used_port}\n"
                f"🆔 UUID: {client_id}\n"
                f"🌐 Адрес: {server_ip}\n\n"
                f"⚡ Протокол: VMESS + TCP\n"
                f"🔒 Безопасность: none"
            )
            
            await update.message.reply_text(response)
        else:
            await update.message.reply_text(f"❌ {message}")
            
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка: {str(e)}")

@require_auth  
async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Список пользователей"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT email, port, protocol FROM users")
        users = cursor.fetchall()
        conn.close()
        
        if users:
            users_list = ["📊 Список пользователей:\n"]
            for email, port, protocol in users:
                users_list.append(f"👤 {email} | Порт: {port} | {protocol.upper()}")
            
            await update.message.reply_text("\n".join(users_list))
        else:
            await update.message.reply_text("❌ Пользователи не найдены")
            
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка: {str(e)}")

@require_auth
async def restart_xray_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Перезапуск Xray (БЕЗ ПАРОЛЯ!)"""
    success, message = restart_xray()
    if success:
        await update.message.reply_text("✅ " + message)
    else:
        await update.message.reply_text("❌ " + message)

@require_auth
async def change_password_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Смена пароля (БЕЗ СТАРОГО ПАРОЛЯ!)"""
    if len(context.args) != 1:
        await update.message.reply_text("❌ Использование: /change_password <новый_пароль>")
        return
    
    new_password = context.args[0]
    change_password(new_password)
    await update.message.reply_text("✅ Пароль успешно изменен!")

# ===== ЗАПУСК БОТА =====
def main():
    """Основная функция запуска бота"""
    # Инициализация БД
    init_db()
    
    # Создаем приложение бота
    application = Application.builder().token(config.BOT_TOKEN).build()
    
    # Регистрируем обработчики команд
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("add_vmess", add_vmess))
    application.add_handler(CommandHandler("list_users", list_users))
    application.add_handler(CommandHandler("restart_xray", restart_xray_command))
    application.add_handler(CommandHandler("change_password", change_password_command))
    
    # Запускаем бота
    logger.info("Бот запускается...")
    print("🤖 Бот для управления Xray запускается...")
    print(f"💡 Дефолтный пароль: {config.ADMIN_PASSWORD}")
    
    application.run_polling()

if __name__ == '__main__':
    main()
