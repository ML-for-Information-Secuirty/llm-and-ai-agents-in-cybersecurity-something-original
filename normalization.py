from pathlib import Path
import os
import json

from typing import Dict
import yaml
from tqdm import tqdm


def normalize_log(raw_event: dict) -> dict:
    """Парсит сырой JSON Sysmon в нормализованный формат."""

    normalized = {}

    event = raw_event.get('Event', {})
    system = event.get('System', {})
    event_data_list = event.get('EventData', {}).get('Data', [])

    fields = {item['Name']: item.get('text', '') for item in event_data_list if 'Name' in item}

    normalized['msgid'] = system.get('EventID', '')

    raw_time = system.get('TimeCreated', {}).get('SystemTime', '')
    normalized['time'] = raw_time[:23] + 'Z' if len(raw_time) > 23 else raw_time

    normalized['event_src.host'] = system.get('Computer', 'unknown')

    subj_path = fields.get('Image', '')
    subj_name = subj_path.split('\\')[-1] if subj_path else ''
    subj_dir = '\\'.join(subj_path.split('\\')[:-1]) + '\\' if subj_path else ''

    normalized['subject.process.id'] = fields.get('ProcessId', '')
    normalized['subject.process.parent.id'] = fields.get('ParentProcessId', '')
    normalized['subject.process.fullpath'] = subj_path
    normalized['subject.process.name'] = subj_name
    normalized['subject.process.path'] = subj_dir
    normalized['subject.process.cmdline'] = fields.get('CommandLine', '')
    normalized['subject.process.hash'] = fields.get('Hashes', '')

    user_raw = fields.get('User', '')
    normalized['subject.account.id'] = user_raw

    normalized['subject.account.session_id'] = fields.get('LogonId', '')

    obj_path = fields.get('ParentImage', '')
    if obj_path:
        obj_name = obj_path.split('\\')[-1]
        obj_dir = '\\'.join(obj_path.split('\\')[:-1]) + '\\'
        normalized['object.process.fullpath'] = obj_path
        normalized['object.process.name'] = obj_name
        normalized['object.process.path'] = obj_dir
        normalized['object.process.id'] = fields.get('ParentProcessId', '')

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

        read_json = f_in.read()

        try:
            log_entry = json.loads(read_json)
            normalized = normalize_log(log_entry)

            if taxonomy:
                for key in normalized.keys():
                    if key not in taxonomy.get('Fields', []):
                        print(f"[!] Поле {key} отсутствует в таксономии")

            f_out.write(json.dumps(normalized, ensure_ascii=False) + '\n')

        except json.JSONDecodeError as e:
            print(f"[!] Ошибка чтения JSON: {e}")
        except Exception as e:
            print(f"[!] Ошибка: {e}")


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
            if file_input_path != file_output_path:
                process_log_file(file_input_path, file_output_path, taxonomy)


if __name__ == '__main__':
    root_dir = Path(__file__).resolve().parent
    taxonomy_path = os.path.join(root_dir, "taxonomy_fields", "i18n_en.yaml")
    correlation_path = os.path.join(root_dir, "windows_correlation_rules")
    normalize(taxonomy_path, correlation_path)
