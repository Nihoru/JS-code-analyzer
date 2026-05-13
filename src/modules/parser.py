import os
import requests
import jsbeautifier
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def save_all_js_from_url(url, output_filename="src/output/js_code.txt", separator="\n\n"):
    """
    Скачивает встроенный JS-код и код из внешних файлов (.js),
    подключенных на странице, и сохраняет всё в один файл.
    Каждый вызов перезаписывает файл.
    """
    
    # Создание директории для вывода
    os.makedirs(os.path.dirname(output_filename), exist_ok=True)

    # Открытие файла на запись (очистка при каждом новом запросе)
    with open(output_filename, 'w', encoding='utf-8') as file:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            print(f"Загрузка главной страницы: {url}")
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            script_tags = soup.find_all('script')  # Поиск всех тегов <script>
            
            js_found = False  # Флаг наличия найденного JS
            
            # Конфигурация форматировщика (beautifier)
            opts = jsbeautifier.default_options()
            opts.indent_size = 2

            for idx, script in enumerate(script_tags, start=1):
                script_type = script.get('type', '').lower()
                
                # Игнорирование неисполняемых скриптов (JSON, шаблоны)
                if 'json' in script_type or 'template' in script_type:
                    continue

                src = script.get('src')
                
                if src:
                    # Обработка внешнего скрипта
                    absolute_url = urljoin(url, src)
                    print(f"Скачивание внешнего скрипта [{idx}]: {absolute_url}")
                    try:
                        js_response = requests.get(absolute_url, headers=headers, timeout=15)
                        js_response.raise_for_status()
                        
                        js_content = js_response.text.strip()
                        if js_content:
                            if js_found:
                                file.write(separator)
                            
                            # Попытка форматирования кода
                            try:
                                formatted_js = jsbeautifier.beautify(js_content, opts)
                            except Exception:
                                formatted_js = js_content
                            
                            file.write(f"/* === ВНЕШНИЙ СКРИПТ {idx}: {absolute_url} === */\n")
                            file.write(formatted_js)
                            js_found = True
                            
                    except requests.exceptions.RequestException as e:
                        print(f"  [!] Ошибка при скачивании {absolute_url}: {e}")
            
                else:
                    # Обработка встроенного (inline) кода
                    if script.string:
                        if js_found:
                            file.write(separator)
                        
                        try:
                            formatted_js = jsbeautifier.beautify(script.string.strip(), opts)
                        except Exception:
                            formatted_js = script.string.strip()
                        
                        file.write(f"/* === ВСТРОЕННЫЙ СКРИПТ {idx} === */\n")
                        file.write(formatted_js)
                        js_found = True

            if js_found:
                print(f"\nУспех! Весь JavaScript код собран в файл: {output_filename}")
            else:
                print("\nJavaScript код не найден.")

        except requests.exceptions.RequestException as e:
            print(f"Ошибка при подключении к сайту: {e}")
        except Exception as e:
            print(f"Произошла непредвиденная ошибка: {e}")
