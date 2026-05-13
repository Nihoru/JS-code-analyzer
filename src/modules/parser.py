import os
import shutil
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def prepare_output_dir(dir_path="src/output"):
    """
    Создает директорию, если она не существует. 
    Если существует — удаляет все файлы внутри.
    """
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    else:
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Ошибка при удалении {file_path}: {e}")

def save_all_js_from_url(url, output_filename="src/output/js_code.txt", separator="\n\n"):
    """
    Скачивает как встроенный JS-код, так и код из внешних файлов (.js),
    подключенных на странице, и сохраняет всё в один файл.
    """
    
    output_dir = os.path.dirname(output_filename)
    if output_dir:
        prepare_output_dir(output_dir)

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        print(f"Загрузка главной страницы: {url}")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script')
        
        js_found = False

        with open(output_filename, 'w', encoding='utf-8') as file:
            for idx, script in enumerate(script_tags, start=1):
                script_type = script.get('type', '').lower()
                
                if 'json' in script_type or 'template' in script_type:
                    continue

                src = script.get('src')
                
                
                if src:
                    
                    absolute_url = urljoin(url, src)
                    
                    print(f"Скачивание внешнего скрипта [{idx}]: {absolute_url}")
                    try:
                        js_response = requests.get(absolute_url, headers=headers, timeout=5)
                        js_response.raise_for_status()
                        
                        js_content = js_response.text.strip()
                        if js_content:
                            if js_found:
                                file.write(separator)
                            
                            
                            file.write(f"/* === ВНЕШНИЙ СКРИПТ {idx}: {absolute_url} === */\n")
                            file.write(js_content)
                            js_found = True
                            
                    except requests.exceptions.RequestException as e:
                        print(f"  [!] Ошибка при скачивании {absolute_url}: {e}")
            
                else:
                    if script.string:
                        if js_found:
                            file.write(separator)
                        
                        file.write(f"/* === ВСТРОЕННЫЙ СКРИПТ {idx} === */\n")
                        file.write(script.string.strip())
                        js_found = True

        if js_found:
            print(f"\nУспех! Весь JavaScript код собран в файл: {output_filename}")
        else:
            print("\nJavaScript код не найден.")

    except requests.exceptions.RequestException as e:
        print(f"Ошибка при подключении к главному сайту: {e}")
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")