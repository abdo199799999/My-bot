# mybot.py - الإصدار النهائي (مع إصلاح scan_command)
import logging
import asyncio
import json
import os
import socket
import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters
from telegram.error import BadRequest
from functools import wraps

# --- الإعدادات الأساسية ---
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# --- إعدادات الاشتراك الإجباري ---
FORCE_SUB_CHANNEL_ID = -1003046280171
FORCE_SUB_CHANNEL_LINK = "https://t.me/TheCyberArsenal"

BOT_TOKEN = os.environ.get('BOT_TOKEN')

# --- إدارة اللغات ---
def load_language(lang_code):
    try:
        with open(f'{lang_code}.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        with open('en.json', 'r', encoding='utf-8') as f:
            return json.load(f)

# --- دوال البحث غير المتزامنة ---
async def get_subdomains_from_crtsh(client, domain):
    # ... (الكود هنا لم يتغير)
    logger.info(f"[*] Fetching subdomains from crt.sh for: {domain}")
    subdomains = set()
    try:
        response = await client.get(f'https://crt.sh/?q=%.{domain}&output=json')
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomains.add(entry['name_value'])
            logger.info(f"[+] Found {len(subdomains)} unique subdomains via crt.sh.")
            return subdomains
    except Exception as e:
        logger.error(f"[-] An error occurred with crt.sh: {e}")
    return subdomains

async def get_subdomains_from_otx(client, domain):
    # ... (الكود هنا لم يتغير)
    logger.info(f"[*] Fetching subdomains from AlienVault OTX for: {domain}")
    subdomains = set()
    try:
        response = await client.get(f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns')
        if response.status_code == 200:
            data = response.json()
            for record in data.get('passive_dns', []):
                subdomains.add(record['hostname'])
            logger.info(f"[+] Found {len(subdomains)} unique subdomains via OTX.")
            return subdomains
    except Exception as e:
        logger.error(f"[-] An error occurred with OTX: {e}")
    return subdomains

async def get_ip_info(client, ip):
    # ... (الكود هنا لم يتغير)
    try:
        response = await client.get(f'https://ipinfo.io/{ip}/json')
        return response.json()
    except Exception:
        return {}

async def get_server_header(client, domain):
    # ... (الكود هنا لم يتغير)
    try:
        response = await client.head(f'https://{domain}', follow_redirects=True)
        return response.headers.get('server', 'N/A')
    except Exception:
        return 'N/A'

async def check_port(ip, port):
    # ... (الكود هنا لم يتغير)
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False

# --- دالة التحقق من الاشتراك ---
async def is_user_member(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> bool:
    try:
        member = await context.bot.get_chat_member(chat_id=FORCE_SUB_CHANNEL_ID, user_id=user_id)
        return member.status in ['member', 'administrator', 'creator']
    except BadRequest:
        logger.error("خطأ في التحقق من عضوية المستخدم. تأكد من أن البوت مشرف في القناة وأن المعرّف صحيح.")
        return True
    except Exception as e:
        logger.error(f"خطأ غير متوقع في is_user_member: {e}")
        return True

# --- الديكور (Decorator) للتحقق من الاشتراك ---
def force_subscribe(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        lang_code = context.user_data.get('lang', 'en')
        t = load_language(lang_code)

        if not await is_user_member(context, user_id):
            keyboard = [[InlineKeyboardButton(t["join_channel_button"], url=FORCE_SUB_CHANNEL_LINK)]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            message_sender = update.callback_query.message if update.callback_query else update.message
            await message_sender.reply_text(t["force_subscribe_message"], reply_markup=reply_markup)
            return
        
        return await func(update, context, *args, **kwargs)
    return wrapper

# --- أوامر البوت ---

@force_subscribe
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if 'next_action' in context.user_data:
        del context.user_data['next_action']
    
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
    
    if update.callback_query:
        await update.callback_query.edit_message_text(t["welcome"], reply_markup=reply_markup)
    else:
        await update.message.reply_text(t["welcome"], reply_markup=reply_markup)

# --- هذا هو الجزء الذي تم إصلاحه ---
@force_subscribe
async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang_code = context.user_data.get('lang', 'en')
    t = load_language(lang_code)
    
    if not context.args:
        await update.message.reply_text(t["scan_usage"])
        return
        
    domain_to_scan = context.args[0]
    
    # دائماً نرسل رسالة جديدة ونحفظها في متغير "msg"
    msg = await update.message.reply_text(t["scan_start"].format(domain=domain_to_scan))

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            tasks = [get_subdomains_from_crtsh(client, domain_to_scan), get_subdomains_from_otx(client, domain_to_scan)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_subdomains = set()
        for res in results:
            if isinstance(res, set):
                all_subdomains.update(res)

        if all_subdomains:
            results_text = "\n".join(sorted(list(all_subdomains)))
            # حذف رسالة "جاري البحث..."
            await msg.delete()
            
            if len(results_text.encode('utf-8')) > 4000:
                with open("subdomains.txt", "w", encoding="utf-8") as f:
                    f.write(results_text)
                await context.bot.send_document(chat_id=update.effective_chat.id, document=open("subdomains.txt", "rb"), caption=t["scan_results_file"].format(count=len(all_subdomains)))
                os.remove("subdomains.txt")
            else:
                # إرسال النتائج كرسالة جديدة
                await update.message.reply_text(t["scan_results_text"].format(count=len(all_subdomains), domains=results_text))
        else:
            await msg.edit_text(t["scan_no_results"])
            
    except Exception as e:
        logger.error(f"Scan command error: {e}")
        await msg.edit_text(t["generic_error"])

@force_subscribe
async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
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

@force_subscribe
async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
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

@force_subscribe
async def ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
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
@force_subscribe
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
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
        await start_command(update, context)

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
    next_action = context.user_data.get('next_action')
    if next_action and update.message and update.message.text:
        context.args = update.message.text.split()
        
        command_map = {
            'scan': scan_command,
            'ip': ip_command,
            'info': info_command,
            'ports': ports_command
        }
        
        if next_action in command_map:
            # امسح الإجراء التالي لمنع التكرار
            del context.user_data['next_action']
            await command_map[next_action](update, context)
        
    else:
        await start_command(update, context)

# --- الدالة الرئيسية ---
def main() -> None:
    if not BOT_TOKEN:
        logger.error("FATAL ERROR: BOT_TOKEN not found.")
        return

    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("ip", ip_command))
    application.add_handler(CommandHandler("info", info_command))
    application.add_handler(CommandHandler("ports", ports_command))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

    logger.info("Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main()
