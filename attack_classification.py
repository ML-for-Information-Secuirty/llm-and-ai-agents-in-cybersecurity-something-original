import ollama
import json
from tqdm import tqdm
from pathlib import Path
import os


def classify_with_ollama(logs_json: list[dict], attack_tree: dict, model: str = "qwen2.5:7b-instruct-q4_K_M"):
    """
    Классифицирует лог с помощью локальной Ollama-модели.
    """
    # Формируем промпт с контекстом
    tactics_list = list(attack_tree['tactics'].keys())
    techniques_flat = []
    for techs in attack_tree.values():
        if isinstance(techs, dict):
            techniques_flat.extend(techs.keys())

    prompt = f"""
    You are a cybersecurity analyst. Classify the tactic for these normalized security logs into MITRE ATT&CK framework.
    AVAILABLE TACTICS: {", ".join(tactics_list) + "\n"}
    LOGS TO ANALYZE:
    {"\n".join([json.dumps(log_json, indent=2, ensure_ascii=False) for log_json in logs_json])}
    Select only one tactic strictly from given. Output just the tactic word with no other information and no explanation
    THERE SHOULD BE ONLY ONE ANSWER FOR ALL THE LOGS.
    IN THE ANSWER THERE SHOULD BE ONLY ONE OPTION FROM GIVEN LIST AND NOTHING ELSE."""

    model_options = {"temperature": 0, "seed": 42}
    response = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}], options=model_options)
    tactic_name = response.message.content

    techinques = attack_tree['tactics'][tactic_name]
    techniques_to_choose = []

    for k, v in techinques.items():
        if not v['subtechniques']:
            techniques_to_choose.append(k)
        else:
            for subt in v['subtechniques']:
                techniques_to_choose.append(f"{k}: {subt}")

    prompt_technique = f"""
    You are a cybersecurity analyst. You already classified the tactic for the following logs. It is {tactic_name}.
    Now you need to select only one MITRE ATT&CK framework technique strictly from AVAILABLE TECHNIQUES list which describes the logs the best.
    The option should be one for all logs.
    Output just the technique value with no other information and no explanation.

    LOGS TO ANALYZE:
    {"\n".join([json.dumps(log_json, indent=2, ensure_ascii=False) for log_json in logs_json])}
    AVAILABLE TECHNIQUES (SEPARATED BY SPACE AND COMMA):
    {"\n" + ", ".join(techniques_to_choose)}
    THERE SHOULD BE ONLY ONE ANSWER FOR ALL THE LOGS.
    IN THE ANSWER THERE SHOULD BE ONLY OPTIONS FROM GIVEN LISTS AND NOTHING ELSE.
    """

    response_technique = ollama.chat(model=model, messages=[{"role": "user", "content": prompt_technique}], options=model_options)

    prompt_importance = f"""
    You are a cybersecurity analyst. You already classified the tactic for the following logs. It is {tactic_name}
    You also know the technique - it is {response_technique.message.content.strip()}.
    Now you need to classify the level of importance of the logs. Select only one option from given: low, medium, high.
    The option should be one for all logs.
    Output just the importance value with no other information and no explanation.

    LOGS TO ANALYZE:
    {"\n".join([json.dumps(log_json, indent=2, ensure_ascii=False) for log_json in logs_json])}
    THERE SHOULD BE ONLY ONE ANSWER FOR ALL THE LOGS.
    IN THE ANSWER THERE SHOULD BE ONLY OPTIONS FROM GIVEN LISTS AND NOTHING ELSE.
    """

    response_importance = ollama.chat(model=model, messages=[{"role": "user", "content": prompt_importance}], options=model_options)
    answer = {
        "tactic": tactic_name,
        "technique": response_technique.message.content.strip(),
        "importance": response_importance.message.content.strip(),  
    }

    return answer


if __name__ == "__main__":
    MODEL = "qwen2.5:7b-instruct-q4_K_M"

    root_dir = Path(__file__).resolve().parent
    correlations_path = os.path.join(root_dir, "windows_correlation_rules")
    tree_path = os.path.join(root_dir, "mitre_windows_tree.json")

    with open(tree_path, 'r') as tree_file:
        attack_tree = json.loads(tree_file.read())

    for correlation_folder in tqdm(os.listdir(correlations_path)):

        log_files_folder = os.path.join(correlations_path, correlation_folder, "tests")
        logs_list = []

        for log_file_path in os.listdir(log_files_folder):
            if "norm" in log_file_path:
                with open(os.path.join(log_files_folder, log_file_path), 'r', encoding='utf-8') as log_file:
                    log_json = json.loads(log_file.read())
                    logs_list.append(log_json)

        answer = classify_with_ollama(logs_list, attack_tree, model=MODEL)
        path_parts = [correlations_path, correlation_folder, "answers.json"]

        with open(os.path.join(*path_parts), 'w', encoding='utf-8') as answer_file:
            answer_file.write(json.dumps(answer))
