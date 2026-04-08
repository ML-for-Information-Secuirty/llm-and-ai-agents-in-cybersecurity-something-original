import json
import requests
from collections import defaultdict
from pathlib import Path
import os


def download_mitre_attack_windows(output_file=None):
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    data = response.json()

    techniques = {}
    tactics = {}
    relationships = []

    for obj in data["objects"]:
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            techniques[obj["id"]] = obj
        elif obj_type == "x-mitre-tactic":
            tactics[obj["id"]] = obj
        elif obj_type == "relationship":
            relationships.append(obj)

    def is_windows_platform(obj):
        platforms = obj.get("x_mitre_platforms", [])
        return any("windows" in p.lower() for p in platforms)

    windows_techniques = {tid: t for tid, t in techniques.items() if is_windows_platform(t)}

    tactic_map = {t["x_mitre_shortname"]: t["name"] for t in tactics.values() if "x_mitre_shortname" in t}

    subtech_to_parent = {}
    for rel in relationships:
        if (rel["relationship_type"] == "subtechnique-of" and
            rel["source_ref"] in windows_techniques and
            rel["target_ref"] in windows_techniques):
            subtech_to_parent[rel["source_ref"]] = rel["target_ref"]

    attack_tree = defaultdict(lambda: defaultdict(lambda: {"subtechniques": []}))
    techniques_flat = []
    parent_to_subs = defaultdict(list)

    for tech_id, tech in windows_techniques.items():
        ext_refs = tech.get("external_references", [])
        mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), {})
        tech_name = tech.get("name", "Unknown")

        is_subtechnique = tech.get("x_mitre_is_subtechnique", False)

        for kcp in tech.get("kill_chain_phases", []):
            if kcp.get("kill_chain_name") == "mitre-attack":
                phase = kcp.get("phase_name")
                tactic_display = tactic_map.get(phase)
                if not tactic_display:
                    continue

                if is_subtechnique and tech_id in subtech_to_parent:
                    parent_id = subtech_to_parent[tech_id]
                    parent_ext = next((r for r in techniques[parent_id].get("external_references", []) 
                                      if r.get("source_name") == "mitre-attack"), {})
                    parent_name = techniques[parent_id].get("name", "Unknown")
                    parent_to_subs[parent_name].append(tech_name)
                else:
                    attack_tree[tactic_display][tech_name]["subtechniques"] = []

    for parent_name, subs in parent_to_subs.items():
        subs.sort()
        for tactic_display, techniques_dict in attack_tree.items():
            if parent_name in techniques_dict:
                techniques_dict[parent_name]["subtechniques"] = list(set(subs))
                break

    for tactic_name, techniques_dict in attack_tree.items():
        for tech_name, tech_info in techniques_dict.items():
            if tech_info["subtechniques"]:
                for sub in tech_info["subtechniques"]:
                    techniques_flat.append(f"{tech_name}: {sub}")
            else:
                techniques_flat.append(tech_name)

    techniques_flat.sort()

    result = {
        "tactics": {k: dict(v) for k, v in attack_tree.items()},
        "techniques_flat": list(set(techniques_flat))
    }

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    return result


def get_windows_techniques_by_tactic(attack_tree, tactic_name):
    return list(attack_tree.get("tactics", {}).get(tactic_name, {}).keys())


def get_all_windows_techniques_flat(attack_tree):
    return attack_tree.get("techniques_flat", [])


def search_techniques(attack_tree, query):
    query_lower = query.lower()
    results = []
    for tactic, techniques in attack_tree.get("tactics", {}).items():
        for tech_name in techniques.keys():
            if query_lower in tech_name.lower():
                results.append(f"[{tactic}] {tech_name}")
    return results


if __name__ == "__main__":

    root_dir = Path(__file__).resolve().parent
    cache_file = os.path.join(root_dir, "mitre_windows_tree.json")

    if os.path.exists(cache_file):
        print(f"[*] Загрузка кэшированного дерева из {cache_file}...")
        with open(cache_file, 'r', encoding='utf-8') as f:
            attack_tree = json.load(f)
    else:
        attack_tree = download_mitre_attack_windows(output_file=cache_file)
