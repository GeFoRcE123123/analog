# Обновление интерфейса настроек парсеров

## ✅ Изменения

### Удалено:
1. ❌ **HTML Парсер** - секция полностью удалена (не работает)
2. ❌ **Red Hat Importer** - секция полностью удалена (не используется)

### Оставлено:
1. ✅ **NVD Парсер** - единственный рабочий парсер
   - Включен по умолчанию (`checked`)
   - Настройки активны (убраны `opacity-50` и `disabled`)
   - Значение по умолчанию: 30 дней
   - Добавлена информация о последнем успешном парсинге

## 🔧 Обновленный JavaScript

### Функция `getParserSettings()`:
```javascript
function getParserSettings() {
    const nvdEnabled = document.getElementById('enableNvdParser').checked;
    const nvdDays = parseInt(document.getElementById('nvdDays').value) || 30;
    
    return {
        sources: [], // HTML парсер отключен
        limit_per_source: 0,
        enable_nvd: nvdEnabled,
        enable_redhat: false, // RedHat парсер отключен
        nvd_days: nvdDays
    };
}
```

### Event Listeners:
- Удалены обработчики для HTML и RedHat парсеров
- Оставлен только обработчик для NVD парсера

## 📊 Результат

Теперь в интерфейсе отображается только **NVD Парсер** с:
- ✅ Переключателем включенным по умолчанию
- ✅ Активным полем для ввода количества дней (30 по умолчанию)
- ✅ Информацией о последнем успешном парсинге (4,948 уязвимостей)

## ✅ Деплой

Файл обновлен на:
- ✅ Backend VM (`~/vulnerability_manager/backend/templates/parsers.html`)
- ✅ Frontend VM (`~/vulnerability_manager/frontend/templates/parsers.html`)

После перезагрузки страницы интерфейс будет показывать только рабочий NVD парсер.

