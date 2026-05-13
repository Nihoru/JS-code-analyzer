import re
from modules.analyzer import VULNERABILITY_RULES, get_js_code_from_file, is_meaningful_line

def calculate_infection_rate(js_file_path):
    """
    Рассчитывает заражённость программного кода по формуле:
    M = P(A) * P(B) * 100%
    P(A) = m1 / n
    P(B) = m2 / n (но не более 1)
    
    n - количество содержательных строчек кода
    m1 - количество заражённых содержательных строчек кода
    m2 - количество дыр в безопасности (уязвимостей)
    """
    try:
        js_code = get_js_code_from_file(js_file_path)  # Считывание кода
    except Exception:
        return 0, 0, 0, 0
        
    lines = js_code.splitlines()  # Разделение на строки
    
    # Фильтрация содержательных строк
    meaningful_indices = [i for i, line in enumerate(lines) if is_meaningful_line(line)]
    n = len(meaningful_indices)  # Общее кол-во содержательных строк
    
    if n == 0:
        return 0.0, 0, 0, 0
    
    lines_with_vulns = set()  # Множество индексов строк с уязвимостями
    m2 = 0                    # Общее количество найденных уязвимостей
    
    for rule in VULNERABILITY_RULES:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        for i, line in enumerate(lines):
            if pattern.search(line):
                m2 += 1  # Уязвимостей может быть больше, чем строк
                if is_meaningful_line(line):
                    lines_with_vulns.add(i)
                
    m1 = len(lines_with_vulns)  # Кол-во уникальных зараженных строк
    
    pa = m1 / n  # Вероятность того, что выбранная строка заражена
    pb = m2 / n  # Плотность уязвимостей на строку
    if pb > 1:
        pb = 1
        
    m = pa * pb * 100  # Итоговый процент зараженности
    return round(m, 2), m1, m2, n
