
#!/bin/bash

# Проверяем существование файла live
if [ ! -f "live" ]; then
    echo "Файл 'live' не найден!"
    exit 1
fi

# Очищаем файл banners
> banners

echo "Начинаем массовое сканирование..."

# Читаем каждый IP из файла live и запускаем ./z
while read -r ip; do
    # Пропускаем пустые строки
    if [ -z "$ip" ]; then
        continue
    fi
    
    echo "Сканируем $ip:2601..."
    echo "=== Сканирование $ip ===" >> banners
    
    # Запускаем ./z с правильными параметрами
    # IP, порт 2601, 50 потоков, 500 pps, 5 секунд
    ./z "$ip" 2601 50 500 5 >> banners 2>&1
    
    echo "Завершено сканирование $ip"
    echo "" >> banners
    
done < live

echo "Массовое сканирование завершено. Результаты в файле 'banners'"
