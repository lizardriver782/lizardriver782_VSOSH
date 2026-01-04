import asyncio
from aiogram import Bot, Dispatcher, types
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.filters import Command, CommandStart
from aiogram import F
from pathlib import Path
import os
import yara


API_TOKEN = "8531534591:AAEscH7DlXiXI2Qzo8v1yOjrSn9bAFqLqwY"


YARA_RULES_PATH = Path(
    r"C:\Users\dmitr\yara"
)

bot = Bot(token=API_TOKEN)
dp = Dispatcher()

button_analyze = KeyboardButton(text="Анализировать файл на вредоносность")
button_filetype = KeyboardButton(text="Узнать настоящий тип файла")

keyboard = ReplyKeyboardMarkup(
    keyboard=[[button_analyze], [button_filetype]], resize_keyboard=True
)

MAGIC_TABLE = [
    # Формат, расширения, hex сигнатура, смещение
    ("7-Zip archive", ["7z"], "37 7A BC AF 27 1C", 0),
    ("BZIP2 compressed", ["bz2"], "42 5A 68", 0),
    ("GZIP compressed", ["gz"], "1F 8B", 0),
    (
        "ZIP archive/RAR/Office Open XML",
        ["zip", "docx", "xlsx", "pptx", "jar", "apk"],
        "50 4B 03 04",
        0,
    ),
    ("ZIP archive (empty)", ["zip"], "50 4B 05 06", 0),
    ("ZIP archive (spanned)", ["zip"], "50 4B 07 08", 0),
    ("RAR archive", ["rar"], "52 61 72 21 1A 07 00", 0),
    ("RAR archive v5", ["rar"], "52 61 72 21 1A 07 01 00", 0),
    ("TAR archive", ["tar"], "75 73 74 61 72", 257),
    ("Portable Document Format", ["pdf"], "25 50 44 46", 0),
    ("JPEG image", ["jpg", "jpeg"], "FF D8 FF", 0),
    ("PNG image", ["png"], "89 50 4E 47 0D 0A 1A 0A", 0),
    ("GIF image", ["gif"], "47 49 46 38", 0),
    ("GIF image (animated)", ["gif"], "47 49 46 38 39 61", 0),
    ("BMP image", ["bmp"], "42 4D", 0),
    ("TIFF image (little-endian)", ["tif", "tiff"], "49 49 2A 00", 0),
    ("TIFF image (big-endian)", ["tif", "tiff"], "4D 4D 00 2A", 0),
    ("Windows icon", ["ico"], "00 00 01 00", 0),
    ("Windows cursor", ["cur"], "00 00 02 00", 0),
    ("Windows Metafile", ["wmf"], "D7 CD C6 9A", 0),
    ("WebP image", ["webp"], "52 49 46 46", 0),
    ("MPEG-1/2 Audio Layer III", ["mp3"], "49 44 33", 0),
    ("MPEG-1/2 Audio Layer III (no ID3)", ["mp3"], "FF FB", 0),
    ("Waveform Audio", ["wav"], "52 49 46 46", 0),
    ("Audio Video Interleave", ["avi"], "52 49 46 46", 0),
    ("MPEG-4 video/QuickTime", ["mp4", "m4v", "mov"], "66 74 79 70", 4),
    ("MPEG-2 video", ["mpg", "mpeg"], "00 00 01 BA", 0),
    ("FLAC audio", ["flac"], "66 4C 61 43", 0),
    ("Ogg Vorbis", ["ogg", "oga"], "4F 67 67 53", 0),
    (
        "Windows Media Audio",
        ["wma"],
        "30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C",
        0,
    ),
    (
        "Windows Media Video",
        ["wmv"],
        "30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C",
        0,
    ),
    ("Executable and Linkable Format", ["elf"], "7F 45 4C 46", 0),
    ("Portable Executable", ["exe", "dll", "sys"], "4D 5A", 0),
    ("Mach-O binary", ["mach"], "FE ED FA CE", 0),
    ("Mach-O binary (64-bit)", ["mach"], "FE ED FA CF", 0),
    ("Java class file", ["class"], "CA FE BA BE", 0),
    (
        "SQLite database",
        ["sqlite", "db"],
        "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00",
        0,
    ),
    ("Windows Registry hive", ["dat", "regtrans-ms"], "72 65 67 66", 0),
    ("Microsoft Cabinet", ["cab"], "4D 53 43 46", 0),
    ("ISO 9660 CD/DVD image", ["iso"], "43 44 30 30 31", 32769),
    ("Virtual Hard Disk", ["vhd", "vhdx"], "63 6F 6E 6E 65 63 74 69 78", 0),
    ("Windows Shortcut", ["lnk"], "4C 00 00 00 01 14 02 00", 0),
    ("Rich Text Format", ["rtf"], "7B 5C 72 74 66 31", 0),
    ("Windows Executable (COM)", ["com"], "E9", 0),
    ("Apple Disk Image", ["dmg"], "78 01 73 0D 62 62 60", 0),
    ("Ext filesystem", ["ext", "ext2", "ext3", "ext4"], "53 EF", 1080),
    ("NTFS filesystem", ["ntfs"], "EB 52 90 4E 54 46 53 20 20 20 20", 0),
    ("FAT32 filesystem", ["fat32"], "EB 58 90 4D 53 44 4F 53 35 2E 30", 0),
    ("FAT12/FAT16 filesystem", ["fat", "fat16"], "EB 3C 90 4D 53 44 4F 53 35 2E 30", 0),
    ("XML document", ["xml"], "3C 3F 78 6D 6C 20", 0),
    ("HTML document", ["html", "htm"], "3C 21 44 4F 43 54 59 50 45", 0),
    ("UTF-8 with BOM", ["txt", "csv", "etc"], "EF BB BF", 0),
    ("UTF-16 (LE) with BOM", ["txt", "csv", "etc"], "FF FE", 0),
    ("UTF-16 (BE) with BOM", ["txt", "csv", "etc"], "FE FF", 0),
    ("UTF-32 (LE) with BOM", ["txt"], "FF FE 00 00", 0),
    ("UTF-32 (BE) with BOM", ["txt"], "00 00 FE FF", 0),
    ("Microsoft Office (legacy)", ["doc", "xls", "ppt"], "D0 CF 11 E0 A1 B1 1A E1", 0),
    ("OpenDocument Text", ["odt"], "50 4B 03 04", 0),
    ("OpenDocument Spreadsheet", ["ods"], "50 4B 03 04", 0),
    ("OpenDocument Presentation", ["odp"], "50 4B 03 04", 0),
    ("Photoshop document", ["psd"], "38 42 50 53", 0),
    ("TrueType font", ["ttf"], "00 01 00 00 00", 0),
    ("OpenType font", ["otf"], "4F 54 54 4F", 0),
    ("WOFF font", ["woff"], "77 4F 46 46", 0),
    ("WOFF2 font", ["woff2"], "77 4F 46 32", 0),
    ("Windows bitmap font", ["fon"], "4D 5A", 0),
    ("Python bytecode", ["pyc"], "61 0D 0D 0A", 0),
    ("Java Archive", ["jar"], "50 4B 03 04", 0),
    ("Android Package", ["apk"], "50 4B 03 04", 0),
    ("iOS App Package", ["ipa"], "50 4B 03 04", 0),
    ("Adobe Flash", ["swf"], "43 57 53", 0),
    ("Adobe Flash (compressed)", ["swf"], "46 57 53", 0),
    ("Windows thumbnail", ["db"], "FF D8 FF E0 00 10 4A 46 49 46 00 01", 0),
    ("Torrent file", ["torrent"], "64 38 3A 61 6E 6E 6F 75 6E 63 65", 0),
    ("Windows Prefetch", ["pf"], "53 43 43 41", 0),
    ("Windows Event Log", ["evt"], "30 00 00 00 4C 66 4C 65", 0),
    ("Windows Event Log (Vista+)", ["evtx"], "45 6C 66 46 69 6C 65", 0),
    ("Linux package (RPM)", ["rpm"], "ED AB EE DB", 0),
    ("Linux package (DEB)", ["deb"], "21 3C 61 72 63 68 3E", 0),
    ("Apple Keynote", ["key"], "50 4B 03 04", 0),
    ("Apple Numbers", ["numbers"], "50 4B 03 04", 0),
    ("Apple Pages", ["pages"], "50 4B 03 04", 0),
    ("MIDI audio", ["mid", "midi"], "4D 54 68 64", 0),
    ("Adobe Illustrator", ["ai"], "25 50 44 46", 0),
    ("PostScript", ["ps", "eps"], "25 21 50 53", 0),
    ("Adobe InDesign", ["indd"], "06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D", 0),
    (
        "Microsoft Access",
        ["mdb", "accdb"],
        "00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74",
        0,
    ),
    ("Windows Help", ["hlp"], "00 00 FF FF FF FF", 0),
    ("Windows Compiled Help", ["chm"], "49 54 53 46", 0),
    ("Windows Memory Dump", ["dmp"], "50 41 47 45 44 55 4D 50", 0),
    ("Linux core dump", ["core"], "7F 45 4C 46", 0),
    ("VirtualBox disk", ["vdi"], "3C 3C 3C 20 4F 72 61 63 6C 65 20 56 4D 20 56 69", 0),
    ("VMware disk", ["vmdk"], "4B 44 4D", 0),
    ("QEMU disk", ["qcow", "qcow2"], "51 46 49", 0),
    ("Android boot image", ["img"], "41 4E 44 52 4F 49 44 21", 0),
    ("Intel HEX", ["hex"], "3A", 0),
    ("Motorola S-Record", ["srec", "s19"], "53", 0),
    ("Windows Task Scheduler", ["job"], "00 00 00 00", 0),
]


def hex_string_to_bytes(hex_str: str) -> bytes:
    """Конвертирует строку с hex значениями в байты"""
    hex_clean = hex_str.replace(" ", "").upper()
    return bytes.fromhex(hex_clean)


def match_signature(data: bytes, hex_signature: str, offset: int = 0) -> bool:
    """Проверяет соответствие сигнатуры на указанном смещении"""
    signature_bytes = hex_string_to_bytes(hex_signature)
    if offset + len(signature_bytes) > len(data):
        return False
    return data[offset : offset + len(signature_bytes)] == signature_bytes


async def analyze_file_signature(file_path: Path) -> str:
    """Анализирует файл по его сигнатуре (магическим байтам) на основе MAGIC_TABLE"""
    if not file_path.exists():
        return "Ошибка: файл не найден"

    try:
        with file_path.open("rb") as f:

            file_data = f.read(0x9000)

            if len(file_data) == 0:
                return "Ошибка: файл пустой"

            matches = []

            for format_name, extensions, hex_signature, offset in MAGIC_TABLE:
                if match_signature(file_data, hex_signature, offset):
                    matches.append((format_name, extensions, hex_signature, offset))

            if matches:
                # Для специальных случаев с одинаковыми сигнатурами нужна дополнительная проверка
                for format_name, extensions, hex_signature, offset in matches:
                    # RIFF файлы (WebP, WAV, AVI)
                    if hex_signature == "52 49 46 46" and len(file_data) >= 12:
                        if file_data[8:12] == b"WEBP":
                            return f"Тип файла: WebP image"
                        elif file_data[8:12] == b"WAVE":
                            return f"Тип файла: Waveform Audio (WAV)"
                        elif file_data[8:12] == b"AVI ":
                            return f"Тип файла: Audio Video Interleave (AVI)"

                    # ZIP файлы (много форматов используют ZIP)
                    elif hex_signature == "50 4B 03 04":
                        # Читаем больше данных для анализа ZIP структуры
                        f.seek(0)
                        zip_data = f.read(min(8192, file_path.stat().st_size))
                        if len(zip_data) > 30:
                            zip_content = zip_data[30:].lower()

                            # Office Open XML документы
                            if (
                                b"word/" in zip_content
                                or b"document.xml" in zip_content
                            ):
                                return "Тип файла: Office Open XML document (DOCX)"
                            elif b"xl/" in zip_content or b"worksheets/" in zip_content:
                                return "Тип файла: Office Open XML spreadsheet (XLSX)"
                            elif b"ppt/" in zip_content or b"slides/" in zip_content:
                                return "Тип файла: Office Open XML presentation (PPTX)"

                            # JAR/APK/IPA
                            elif (
                                b"meta-inf" in zip_content
                                or b"manifest.mf" in zip_content
                            ):
                                if b"androidmanifest.xml" in zip_content:
                                    return "Тип файла: Android Package (APK)"
                                else:
                                    return "Тип файла: Java Archive (JAR)"

                            # ODF документы
                            elif b"mimetype" in zip_content:
                                odf_pos = zip_content.find(b"mimetype")
                                if odf_pos != -1 and odf_pos < 100:
                                    mime_start = odf_pos + 8
                                    if mime_start < len(zip_content):
                                        mime_data = zip_content[
                                            mime_start : mime_start + 50
                                        ]
                                        if b"opendocument.text" in mime_data:
                                            return "Тип файла: OpenDocument Text (ODT)"
                                        elif b"opendocument.spreadsheet" in mime_data:
                                            return "Тип файла: OpenDocument Spreadsheet (ODS)"
                                        elif b"opendocument.presentation" in mime_data:
                                            return "Тип файла: OpenDocument Presentation (ODP)"

                            # Apple iWork
                            elif (
                                b"preview.jpg" in zip_content
                                or b"preview.pdf" in zip_content
                            ):
                                if b"index.xml" in zip_content:
                                    return f"Тип файла: {format_name}"

                            # Обычный ZIP
                            return f"Тип файла: ZIP archive"

                    # MP4/QuickTime (ftyp на смещении 4)
                    elif hex_signature == "66 74 79 70" and len(file_data) >= 12:
                        ftyp_type = file_data[8:12]
                        if ftyp_type in [b"mp41", b"mp42", b"isom", b"avc1"]:
                            return "Тип файла: MPEG-4 video (MP4)"
                        elif ftyp_type == b"qt  ":
                            return "Тип файла: QuickTime video (MOV)"
                        elif ftyp_type[:2] == b"3g":
                            return "Тип файла: 3GP/3G2 multimedia file"

                    # Для остальных форматов, если подошло
                    else:
                        return f"Тип файла: {format_name}"

            ext = file_path.suffix.lower().lstrip(".")
            extension_map = {
                "txt": "Text file",
                "py": "Python script",
                "js": "JavaScript file",
                "html": "HTML file",
                "htm": "HTML file",
                "css": "CSS stylesheet",
                "json": "JSON data file",
                "csv": "CSV data file",
                "md": "Markdown file",
                "log": "Log file",
                "bat": "Batch script",
                "sh": "Shell script",
                "ps1": "PowerShell script",
                "vbs": "VBScript file",
                "reg": "Windows Registry file",
            }
            if ext in extension_map:
                return f"Тип файла: {extension_map[ext]} (определено по расширению)"

            return f"Неизвестный тип файла по сигнатуре. Расширение: {ext if ext else 'нет'}"

    except PermissionError:
        return "Ошибка: нет доступа к файлу"
    except Exception as e:
        return f"Ошибка при анализе файла: {str(e)}"


def compile_rules_from_folder(folder_path: Path):
    rules = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".yar") or filename.endswith(".yara"):
            rule_path = folder_path / filename
            try:
                compiled_rule = yara.compile(filepath=str(rule_path))
                rules.append(compiled_rule)
            except yara.SyntaxError as e:
                print(f"Ошибка в файле {filename}: {e}")
    return rules


def scan_file_with_rules(file_path: Path, rules):
    matches = []
    for rule in rules:
        try:
            match = rule.match(str(file_path))
            if match:
                matches.extend(match)
        except Exception as e:
            print(f"Ошибка при сканировании файла: {e}")
    return matches


# Словарь для хранения путей к файлам пользователей
user_files = {}


@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    welcome_text = """
Здравствуйте! Я — специализированный бот для комплексного анализа безопасности файлов.

📋 **Доступные функции:**
1. 🔍 Анализ файлов на вредоносность
2. 📄 Определение настоящего типа файла

📌 **Порядок работы:**
1. Отправьте файл в качестве документа
2. Выберите тип анализа на клавиатуре снизу
3. Получите отчет

Файлы удаляются автоматически после проверки.
"""
    await message.answer(welcome_text, reply_markup=keyboard, parse_mode="Markdown")

@dp.message(F.document)
async def handle_file(message: types.Message):
    file_id = message.document.file_id
    file_info = await bot.get_file(file_id)
    Path("downloads").mkdir(exist_ok=True)
    download_path = f"downloads/{file_id}_{message.document.file_name}"
    await bot.download_file(file_info.file_path, destination=download_path)
    user_files[message.from_user.id] = download_path
    await message.answer(
        f"Файл '{message.document.file_name}' успешно загружен. Выберите действие на клавиатуре."
    )


@dp.message(F.text == "Анализировать файл на вредоносность")
async def analyze_malware(message: types.Message):
    user_id = message.from_user.id
    if user_id not in user_files:
        await message.answer("Файл не был отправлен")
        return
    file_path = Path(user_files[user_id])

    if not file_path.exists():
        await message.answer("Файл не был отправлен")
        del user_files[user_id]
        return

    if YARA_RULES_PATH is not None:
        folder_with_rules = Path(YARA_RULES_PATH)
    else:
        folder_with_rules = Path("yara_rules")

    if not folder_with_rules.exists():
        await message.answer(
            f"Папка с YARA правилами не найдена по пути: {folder_with_rules.absolute()}\n"
            f"Проверьте путь в переменной YARA_RULES_PATH в коде."
        )
        return

    if not folder_with_rules.is_dir():
        await message.answer(
            f"Указанный путь не является папкой: {folder_with_rules.absolute()}"
        )
        return

    rules = compile_rules_from_folder(folder_with_rules)
    matches = scan_file_with_rules(file_path, rules)

    important_matches = []
    excluded_rules = (
        "IP",
        "domain",
        "url",
        "filename",
        "useragent",
        "file_size",
        "version",
        "compiler",
        "timestamp",
        "digital_signature",
        "author",
        "description",
        "contains_base64",
        "with_sqlite",
    )

    if matches:
        for m in matches:
            if m.rule not in excluded_rules:
                important_matches.append(m)

    if important_matches:
        text = "Подозрение на вредоносный файл! Найдены совпадения:\n"
        for m in important_matches:
            text += f"- {m.rule} из файла {m.namespace}\n"
        await message.answer(text)
    else:
        await message.answer("Файл безопасен! Можно открывать :)")

    try:
        os.remove(file_path)
        if user_id in user_files:
            del user_files[user_id]
    except FileNotFoundError:
        if user_id in user_files:
            del user_files[user_id]
        pass


@dp.message(F.text == "Узнать настоящий тип файла")
async def analyze_filetype(message: types.Message):
    user_id = message.from_user.id
    if user_id not in user_files:
        await message.answer("Файл не был отправлен")
        return
    file_path = Path(user_files[user_id])

    if not file_path.exists():
        await message.answer("Файл не был отправлен")
        del user_files[user_id]
        return
    result = await analyze_file_signature(file_path)
    await message.answer(result)

    try:
        os.remove(file_path)
        if user_id in user_files:
            del user_files[user_id]
    except FileNotFoundError:
        if user_id in user_files:
            del user_files[user_id]
        pass


async def main():
    try:
        bot_info = await bot.get_me()
        print(f"Бот запущен: @{bot_info.username}")
        await dp.start_polling(bot)
    except Exception as e:
        print(f"Ошибка при запуске бота: {e}")
        print("\nВозможные причины:")
        print("1. Неверный токен API - проверьте токен в переменной API_TOKEN")
        print("2. Токен был отозван - получите новый токен у @BotFather")
        print("3. Проблемы с интернет-соединением")
        print("\nКак получить токен:")
        print("1. Откройте Telegram и найдите @BotFather")
        print("2. Отправьте команду /newbot или /token")
        print("3. Следуйте инструкциям для получения токена")
        print("4. Замените значение API_TOKEN в коде на новый токен")


if __name__ == "__main__":
    asyncio.run(main())
