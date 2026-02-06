## Цель

Legacy‑парсеры (папка `services/legacy_parsers/`) исторически сохраняли в БД минимум: `cve_id/title/description/cvss` и часто теряли первоисточник (в `turn.link` подставлялся NVD). Из‑за этого UI “видит” мало данных, а расширять функциональность сложно.

Этот документ описывает **поэтапный план** расширения без моков и с сохранением **реальных** данных со страниц источников.

## Что уже сделано (в коде)

- **Проброс `etc_data` из legacy‑парсеров в `turn.etc`**:
  - `services/legacy_parsers/base_legacy_parser.py` теперь сохраняет `etc_data` в атрибут `vulnerability.etc_data`.
  - `models/legacy_repositories.py` (`_save_to_turn`) теперь мёрджит `vulnerability.etc_data` в `etc` (TEXT JSON).
- **Сохранение реального источника**:
  - `LegacyVulnerabilityRepository._save_to_turn` теперь предпочитает `vulnerability.link/url` для `turn.link`, и только если их нет — использует ссылку на NVD.

Минимальные поля, которые теперь можно ожидать в `turn.etc` для legacy‑записей:

- `parser`, `source`, `source_link`, `category`, `risk_level`, `status`, `approved`, `modifications`

## Базовая модель данных в `turn.etc`

Для расширения без перепиливания схемы используем `turn.etc` (TEXT JSON) и кладём туда нормализованные секции:

- **`raw`**: “сырые” поля страницы (для трассировки и дообработки)
  - `raw.page_title`, `raw.published`, `raw.updated`, `raw.vendor`, `raw.product`, `raw.affected`, `raw.fixed`, `raw.sections`, ...
- **`references`**: массив ссылок на источники/патчи/документацию
  - `[{ "url": "...", "label": "...", "type": "advisory|patch|vendor|exploit|cve" }]`
- **`affected_products`**: нормализованные продукты/версии
  - `[{ "vendor": "...", "product": "...", "versions": ["..."], "platform": "..." }]`
- **`fix` / `mitigation`**: рекомендации
  - `fix.patches`, `fix.workarounds`, `mitigation.steps`

## Поэтапная реализация (без моков)

### Этап A — “Ничего не теряем”

Для каждого legacy‑парсера при парсинге конкретной страницы сохраняем:

- `source_link` (уже есть)
- `raw.page_title`
- `raw.text_excerpt` (первые 1–3k символов текста страницы)
- `references[]` (все `<a href>` c дедупликацией)

Это даёт максимум данных “как есть” и позволяет добавлять нормализацию позже.

### Этап B — Нормализация ключевых полей

Для каждого источника добавляем “понимание” структуры страницы:

- даты `published/updated`
- vendor/product
- affected/fixed versions
- CVSS vector (если есть), CWE (если есть)

### Этап C — Унификация для UI

После того как минимум 3–5 парсеров дают одинаковые структуры:

- отображаем `references`, `affected_products`, `fix/mitigation` в модалке уязвимости (как у NVD‑записей)
- добавляем фильтры/поиск по vendor/product/версии

## Как тестировать (реальные данные)

- запускаем конкретный legacy‑парсер на 1 странице/1 записи
- проверяем в БД:
  - `turn.link` = **URL источника**
  - `turn.etc` содержит `source_link`, `parser`, `raw`/`references` (если добавлены)
- проверяем UI:
  - “Просмотр” уязвимости показывает источники/рефы (после интеграции в шаблон)


