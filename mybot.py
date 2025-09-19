# mybot.py - الإصدار العالمي النهائي
import logging
import asyncio
import json
import os
import socket
import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# --- الإعدادات الأساسية ---
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# اقرأ التوكن من متغيرات البيئة (للنشر الآمن)
# تأكد من أنك ستقوم بإعداد هذا في Koyeb
BOT_TOKEN = os.environ.get('BOT_TOKEN')

# --- إدارة اللغات ---
def load_language(lang_code):
    """تحميل ملف اللغة المحدد"""
    try:
        with open(f'{lang_code}.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # إذا لم يتم العثور على ملف اللغة، استخدم الإنجليزية كخيار افتراضي
        with open('en.json', 'r', encoding='utf-8') as f:
            return json.load(f)

# --- وظائف الأدوات الأساسية (غير متزامنة للأداء العالي) ---

async def get_server_header(client, domain):
    """الحصول على ترويسة الخادم بشكل غير متزامن"""
    try:
        # استخدام HEAD لطلب أسرع
        response = await client.head(f"https://{domain}", timeout=10, follow_redirects=True)
        return response.headers.get('server', 'N/A')
    except Exception:
        return 'N/A'

async def get_ip_info(client, ip):
    """الحصول على معلومات IP من ipinfo.io بشكل غير متزامن"""
    try:
        response = await client.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        response.raise_for_status() # التأكد من أن الطلب ناجح
        return response.json()
    except Exception:
        return {}

async def get_subdomains_from_crtsh(client, domain):
    """الحصول على النطاقات الفرعية من crt.sh بشكل غير متزامن"""
    subdomains = set()
    try:
        response = await client.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=120)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                if name_value:
                    # تنظيف وإضافة النطاقات الفريدة فقط
                    subdomains.update(name.strip() for name in name_value.split('\n') if name.strip().endswith(f".{domain}"))
    except Exception as e:
        logger.error(f"Error with crt.sh: {e}")
    return subdomains

async def get_subdomains_from_otx(client, domain):
    """الحصول على النطاقات الفرعية من AlienVault OTX بشكل غير متزامن"""
    subdomains = set()
    try:
        response = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=120)
        if response.status_code == 200:
            data = response.json()
            for record in data.get('passive_dns', []):
                hostname = record.get('hostname')
                if hostname and hostname.endswith(f".{domain}"):
                    subdomains.add(hostname)
    except Exception as e:
        logger.error(f"Error with OTX: {e}")
    return subdomains

async def check_port(ip, port):
    """فحص منفذ معين بشكل غير متزامن"""
    try:
        # محاولة فتح اتصال بالمنفذ
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
        writer.close()
        await writer.wait_closed()
        return port, True # المنفذ مفتوح
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False # المنفذ مغلق أو لا يمكن الوصول إليه

# --- أوامر البوت ---

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """يعرض رسالة الترحيب مع الأزرار"""
    lang_code = context.user_data.get('lang', 'en')
    t = load_language(lang_code)
    
    keyboard = [
        [InlineKeyboardButton(t["scan_button"], callback_data='scan_tool')],
        [InlineKeyboardButton(t["ip_button"], callback_data='ip_tool')],
        [InlineKeyboardButton(t["info_button"], callback_data='info_tool')],
        [InlineKeyboardButton(t["ports_button"], callback_data='ports_tool')],
        [InlineKeyboardButton("🌐 Language / اللغة", callback_data='change_lang')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # إذا كان الأمر /start جديدًا، أرسل رسالة جديدة. إذا كان تعديلاً، قم بتعديل الرسالة الحالية.
    if update.callback_query:
        await update.callback_query.edit_message_text(t["welcome"], reply_markup=reply_markup)
    else:
        await update.message.reply_text(t["welcome"], reply_markup=reply_markup)


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """ينفذ البحث عن النطاقات الفرعية"""
    lang_code = context.user_data.get('lang', 'en')
    t = load_language(lang_code)
    
    if not context.args:
        await update.message.reply_text(t["scan_usage"])
        return
        
    domain_to_scan = context.args[0]
    msg = await update.message.reply_text(t["scan_start"].format(domain=domain_to_scan))

    try:
        async with httpx.AsyncClient() as client:
            tasks = [get_subdomains_from_crtsh(client, domain_to_scan), get_subdomains_from_otx(client, domain_to_scan)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_subdomains = set()
        for res in results:
            if isinstance(res, set):
                all_subdomains.update(res)

        if all_subdomains:
            results_text = "\n".join(sorted(list(all_subdomains)))
            # إذا كانت النتائج طويلة جدًا، أرسلها كملف
            if len(results_text.encode('utf-8')) > 4000:
                with open("subdomains.txt", "w", encoding="utf-8") as f:
                    f.write(results_text)
                await context.bot.send_document(chat_id=update.effective_chat.id, document=open("subdomains.txt", "rb"), caption=t["scan_results_file"].format(count=len(all_subdomains)))
                os.remove("subdomains.txt")
                await msg.delete() # حذف رسالة "جاري البحث..."
            else:
                await msg.edit_text(t["scan_results_text"].format(count=len(all_subdomains), domains=results_text))
        else:
            await msg.edit_text(t["scan_no_results"])
            
    except Exception as e:
        logger.error(f"Scan command error: {e}")
        await msg.edit_text(t["generic_error"])

async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """يحصل على عنوان IP لنطاق"""
    lang_code = context.user_data.get('lang', 'en')
    t = load_language(lang_code)
    
    if not context.args:
        await update.message.reply_text(t["ip_usage"])
        return
        
    domain = context.args[0]
    try:
        ip_address = socket.gethostbyname(domain)
        await update.message.reply_text(t["ip_result"].format(domain=domain, ip=ip_address), parse_mode='Markdown')
    except socket.gaierror:
        await update.message.reply_text(t["ip_not_found"].format(domain=domain))

async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """يحصل على معلومات متقدمة عن IP أو نطاق"""
    lang_code = context.user_data.get('lang', 'en')
    t = load_language(lang_code)

    if not context.args:
        await update.message.reply_text(t["info_usage"])
        return

    target = context.args[0]
    msg = await update.message.reply_text(t["info_start"].format(target=target))

    try:
        async with httpx.AsyncClient() as client:
            try:
                ip_address = socket.gethostbyname(target)
            except socket.gaierror:
                await msg.edit_text(t["ip_not_found"].format(domain=target))
                return

            info_task = get_ip_info(client, ip_address)
            server_task = get_server_header(client, target)
            ip_info, server_header = await asyncio.gather(info_task, server_task)

            response_text = t["info_header"].format(target=target)
            response_text += f"🌐 IP: `{ip_info.get('ip', 'N/A')}`\n"
            response_text += f"🖥️ Server: `{server_header}`\n"
            response_text += f"🔢 ASN: `{ip_info.get('org', 'N/A')}`\n"
            response_text += f"📍 Country: `{ip_info.get('country', 'N/A')}`\n"
            response_text += f"🏙️ City: `{ip_info.get('city', 'N/A')}`\n"
            response_text += f"👤 Hostname: `{ip_info.get('hostname', 'N/A')}`"
            
            await msg.edit_text(response_text, parse_mode='Markdown')

    except Exception as e:
        logger.error(f"Info command error: {e}")
        await msg.edit_text(t["generic_error"])

async def ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """يفحص المنافذ الشائعة لـ IP أو نطاق"""
    lang_code = context.user_data.get('lang', 'en')
    t = load_language(lang_code)

    if not context.args:
        await update.message.reply_text(t["ports_usage"])
        return

    target = context.args[0]
    msg = await update.message.reply_text(t["ports_start"].format(target=target))

    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        await msg.edit_text(t["ip_not_found"].format(domain=target))
        return

    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080, 8443]
    
    tasks = [check_port(ip_address, port) for port in common_ports]
    results = await asyncio.gather(*tasks)
    
    open_ports = [port for port, is_open in results if is_open]

    if open_ports:
        ports_str = ", ".join(map(str, open_ports))
        await msg.edit_text(t["ports_results"].format(ip=ip_address, ports=ports_str), parse_mode='Markdown')
    else:
        await msg.edit_text(t["ports_no_results"].format(ip=ip_address))

# --- معالجات الأزرار والرسائل ---

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """يعالج الضغط على الأزرار"""
    query = update.callback_query
    await query.answer()
    lang_code = context.user_data.get('lang', 'en')
    t = load_language(lang_code)

    if query.data == 'change_lang':
        keyboard = [
            [InlineKeyboardButton("English 🇬🇧", callback_data='set_lang_en')],
            [InlineKeyboardButton("العربية 🇸🇦", callback_data='set_lang_ar')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(text="Please select your language / يرجى اختيار لغتك:", reply_markup=reply_markup)
    
    elif query.data.startswith('set_lang_'):
        new_lang = query.data.split('_')[-1]
        context.user_data['lang'] = new_lang
        t = load_language(new_lang)
        await query.edit_message_text(text=t["language_changed"])
        await start_command(update, context) # إعادة عرض القائمة الرئيسية باللغة الجديدة

    else:
        tool_prompts = {
            'scan_tool': t["scan_prompt"],
            'ip_tool': t["ip_prompt"],
            'info_tool': t["info_prompt"],
            'ports_tool': t["ports_prompt"]
        }
        prompt_text = tool_prompts.get(query.data)
        if prompt_text:
            await query.edit_message_text(text=prompt_text)
            context.user_data['next_action'] = query.data.replace('_tool', '')

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """يعالج الرسائل النصية بعد الضغط على زر"""
    next_action = context.user_data.get('next_action')
    if next_action and update.message:
        context.args = update.message.text.split()
        
        command_map = {
            'scan': scan_command,
            'ip': ip_command,
            'info': info_command,
            'ports': ports_command
        }
        
        if next_action in command_map:
            await command_map[next_action](update, context)
        
        del context.user_data['next_action']
    else:
        await start_command(update, context)

# --- الدالة الرئيسية ---

def main() -> None:
    """تشغيل البوت"""
    if not BOT_TOKEN:
        logger.error("FATAL ERROR: BOT_TOKEN not found. Please set it as an environment variable.")
        return

    application = Application.builder().token(BOT_TOKEN).build()

    # إضافة المعالجات
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("ip", ip_command))
    application.add_handler(CommandHandler("info", info_command))
    application.add_handler(CommandHandler("ports", ports_command))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

    logger.info("Bot is running... Press Ctrl+C to stop.")
    application.run_polling()

if __name__ == "__main__":
    main()

