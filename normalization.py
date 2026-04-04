from pathlib import Path
import os
import json
import re
from typing import Dict, Any
import yaml
from tqdm import tqdm


def extract_path_parts(fullpath: str) -> tuple:
    """Разбивает путь на имя файла и директорию с завершающим слэшем."""
    if not fullpath:
        return "", "", ""

    name = os.path.basename(fullpath)
    directory = os.path.dirname(fullpath)

    # В примере нормализации путь заканчивается на слэш (например, /bin/)
    if directory and directory != '/':
        path = directory + '/'
    elif directory == '/':
        path = '/'
    else:
        path = ""

    return fullpath, name, path


def truncate_timestamp(iso_time: str) -> str:
    """Обрезает время до миллисекунд по примеру: .969912413Z -> .969Z"""
    if not iso_time:
        return ""
    match = re.match(r"(.+\.\d{3})\d*(Z?)", iso_time)
    if match:
        return match.group(1) + "Z"
    return iso_time


def get_nested(data: Dict, *keys, default=None) -> Any:
    """Безопасное получение вложенных значений."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, default)
        else:
            return default
    return data


def normalize_log(log_entry: Dict) -> Dict:
    """Нормализует одно событие лога."""
    normalized = {}

    process = log_entry.get('process', {})
    audit_token = process.get('audit_token', {})
    executable = process.get('executable', {})

    fullpath = executable.get('path', '')
    f_path, f_name, f_dir = extract_path_parts(fullpath)
    cdhash = process.get('cdhash', '')

    normalized['subject.account.id'] = str(audit_token.get('ruid', ''))
    normalized['subject.account.session_id'] = str(process.get('session_id', ''))
    normalized['subject.process.id'] = str(audit_token.get('pid', ''))
    normalized['subject.process.parent.id'] = str(process.get('ppid', ''))
    normalized['subject.process.fullpath'] = f_path
    normalized['subject.process.name'] = f_name
    normalized['subject.process.path'] = f_dir
    normalized['subject.process.hash'] = f"UNKNOWN:{cdhash}" if cdhash else "UNKNOWN"

    normalized['msgid'] = str(log_entry.get('event_type', ''))
    normalized['time'] = truncate_timestamp(log_entry.get('time', ''))
    normalized['event_src.host'] = "127.0.0.1"


    event_data = log_entry.get('event', {})

    if 'open' in event_data:
        file_info = event_data['open'].get('file', {})
        obj_path = file_info.get('path', '')
        o_path, o_name, o_dir = extract_path_parts(obj_path)

        normalized['object.fullpath'] = o_path
        normalized['object.name'] = o_name
        normalized['object.path'] = o_dir

    elif 'fork' in event_data:
        child_info = event_data['fork'].get('child', {})
        child_exec = child_info.get('executable', {})
        obj_path = child_exec.get('path', '')
        o_path, o_name, o_dir = extract_path_parts(obj_path)

        normalized['object.process.fullpath'] = o_path
        normalized['object.process.name'] = o_name
        normalized['object.process.path'] = o_dir

    return normalized


def load_taxonomy_fields(taxonomy_path: str) -> Dict:
    """Загружает таксономию полей из YAML файла (если существует)."""
    taxonomy = {}

    try:
        with open(taxonomy_path, 'r', encoding='utf-8') as f:
            taxonomy = yaml.safe_load(f) or {}
        print(f"[+] Загружена таксономия из {taxonomy_path}")
    except yaml.YAMLError as e:
        print(f"[!] Ошибка парсинга YAML: {e}")
    except Exception as e:
        print(f"[!] Ошибка загрузки таксономии: {e}")

    return taxonomy


def process_log_file(input_file: str, output_file: str, taxonomy: dict):
    """Обрабатывает файл с логами и записывает нормализованные данные."""

    with open(input_file, 'r', encoding='utf-8') as f_in, \
         open(output_file, 'w', encoding='utf-8') as f_out:

        for line_num, line in enumerate(f_in, 1):
            line = line.strip()
            if not line:
                continue

            try:
                log_entry = json.loads(line)
                normalized = normalize_log(log_entry)

                # Валидация по таксономии (если загружена)
                if taxonomy:
                    for key in normalized.keys():
                        if key not in taxonomy.get('allowed_fields', []):
                            print(f"[!] Поле {key} отсутствует в таксономии")
                            break

                f_out.write(json.dumps(normalized, ensure_ascii=False) + '\n')

            except json.JSONDecodeError as e:
                print(f"[!] Ошибка JSON в строке {line_num}: {e}")
            except Exception as e:
                print(f"[!] Ошибка обработки строки {line_num}: {e}")


def normalize(taxonomy_path: str, correlation_path: str):
    """Основная функция нормализации логов."""

    taxonomy = load_taxonomy_fields(taxonomy_path)
    input_folders = os.listdir(correlation_path)

    for input_folder in tqdm(input_folders):
        input_path = os.path.join(correlation_path, input_folder, "tests")

        for file in os.listdir(input_path):
            file_input_path = os.path.join(input_path, file)
            output_file = file.replace("events", "norm_fields")
            file_output_path = os.path.join(input_path, output_file)
            process_log_file(file_input_path, file_output_path, taxonomy)


if __name__ == '__main__':
    root_dir = Path(__file__).resolve().parent
    taxonomy_path = os.path.join(root_dir, "taxonomy_fields", "i18n_en.yaml")
    correlation_path = os.path.join(root_dir, "windows_correlation_rules")
    normalize(taxonomy_path, correlation_path)
