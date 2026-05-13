import re
from modules.analyzer import VULNERABILITY_RULES, get_js_code_from_file

def calculate_infection_rate(js_file_path):
    """
    Рассчитывает заражённость программного кода по формуле:
    M = P(A) * P(B) * 100%
    P(A) = m1 / n
    P(B) = m2 / n (но не более 1)
    n - количество строчек кода
    m1 - количество заражённых строчек кода
    m2 - количество дыр в безопасности (уязвимостей)
    """
    try:
        js_code = get_js_code_from_file(js_file_path)
    except Exception:
        return 0, 0, 0, 0
        
    lines = js_code.splitlines()
    n = len(lines)
    if n == 0:
        return 0.0, 0, 0, 0
    
    lines_with_vulns = set()
    m2 = 0
    
    for rule in VULNERABILITY_RULES:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        for i, line in enumerate(lines):
            if pattern.search(line):
                lines_with_vulns.add(i)
                m2 += 1
                
    m1 = len(lines_with_vulns)
    
    pa = m1 / n
    pb = m2 / n
    if pb > 1:
        pb = 1
        
    m = pa * pb * 100
    return round(m, 2), m1, m2, n
