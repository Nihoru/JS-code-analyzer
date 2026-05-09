import re
from typing import List, Tuple

# Словарь угроз: название, уровень, критичность (1-5, где 5 - самый опасный)
VULNERABILITY_RULES = [
    {
        "name": "eval() function usage",
        "pattern": r"\beval\s*\(",
        "level": "BLOCKER",
        "level_num": 5,
        "description": "eval() executes arbitrary code and is a major security risk"
    },
    {
        "name": "innerHTML / outerHTML injection",
        "pattern": r"\.innerHTML\s*=|\$\.html\s*\(|\.outerHTML\s*=",
        "level": "CRITICAL",
        "level_num": 4,
        "description": "Potential XSS via direct HTML assignment"
    },
    {
        "name": "document.write() usage",
        "pattern": r"document\.write\s*\(",
        "level": "CRITICAL",
        "level_num": 4,
        "description": "document.write can lead to XSS if user input is used"
    },
    {
        "name": "setTimeout / setInterval with string",
        "pattern": r"(setTimeout|setInterval)\s*\(\s*['\"`]",
        "level": "MAJOR",
        "level_num": 3,
        "description": "String-based timer functions mimic eval behavior"
    },
    {
        "name": "Potential prototype pollution",
        "pattern": r"\.__proto__\s*\[|\['__proto__'\]|\.constructor\.prototype",
        "level": "BLOCKER",
        "level_num": 5,
        "description": "Prototype pollution can lead to denial of service or RCE"
    },
    {
        "name": "Unsafe fetch / XHR with user data",
        "pattern": r"(fetch|XMLHttpRequest|\.post|\.get)\s*\([^)]*\+",
        "level": "MAJOR",
        "level_num": 3,
        "description": "Dynamic URL concatenation may cause SSRF or injection"
    },
    {
        "name": "localStorage / sessionStorage with sensitive data",
        "pattern": r"(localStorage|sessionStorage)\.(setItem|getItem)\s*\([^)]*(password|token|secret|key)",
        "level": "MINOR",
        "level_num": 2,
        "description": "Storing sensitive data in web storage is risky"
    },
    {
        "name": "console.log of sensitive data",
        "pattern": r"console\.(log|debug|info)\s*\([^)]*(password|token|secret|key|credential)",
        "level": "INFO",
        "level_num": 1,
        "description": "Sensitive data may leak to browser console"
    }
]

def get_js_code_from_file(file_path: str) -> str:
    """Читает JS код из файла"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def analyze_code_js(site_url: str, js_file_path: str) -> Tuple[str, int, int, int, int, int, int, str]:
    """
    Первая функция: возвращает агрегированную статистику по уязвимостям.
    
    Возвращает кортеж:
    (Ссылка, кол-во чистых строк, угроз 1 уровня, 2, 3, 4, 5, рекомендации)
    """
    # Читаем код
    js_code = get_js_code_from_file(js_file_path)
    lines = js_code.splitlines()
    total_lines = len(lines)
    
    # Считаем уязвимости по уровням
    level_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    lines_with_vulns = set()
    
    for rule in VULNERABILITY_RULES:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        level_num = rule["level_num"]
        
        for i, line in enumerate(lines):
            if pattern.search(line):
                lines_with_vulns.add(i)
                level_counts[level_num] += 1
    
    clean_lines = total_lines - len(lines_with_vulns)
    
    # Рекомендации оставляем пустыми
    recommendations = ""
    
    return (
        site_url,
        clean_lines,
        level_counts[1],  # INFO
        level_counts[2],  # MINOR
        level_counts[3],  # MAJOR
        level_counts[4],  # CRITICAL
        level_counts[5],  # BLOCKER
        recommendations
    )

def get_vulnerabilities_detailed(site_url: str, js_file_path: str) -> List[str]:
    """
    Вторая функция: возвращает массив строк с деталями каждой уязвимости.
    
    Каждая строка имеет формат:
    "Уязвимость: {name} | Уровень: {level} | Строки: {номера_строк}"
    """
    js_code = get_js_code_from_file(js_file_path)
    lines = js_code.splitlines()
    detailed_report = []
    
    for rule in VULNERABILITY_RULES:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        vulnerable_lines = []
        
        for i, line in enumerate(lines, start=1):  # Нумерация строк с 1
            if pattern.search(line):
                # Сохраняем номер строки и саму строку (обрезаем длинные)
                line_preview = line.strip()[:100]
                vulnerable_lines.append(f"строка {i}: {line_preview}")
        
        if vulnerable_lines:
            # Формируем строку с деталями
            vuln_str = f"Уязвимость: {rule['name']} | Уровень: {rule['level']} | {', '.join(vulnerable_lines[:3])}"
            if len(vulnerable_lines) > 3:
                vuln_str += f" (+ еще {len(vulnerable_lines) - 3})"
            detailed_report.append(vuln_str)
    
    return detailed_report