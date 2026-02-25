# Шаблоны инцидентов DFIR-IRIS для РФ

Шаблоны кейсов для DFIR-IRIS, адаптированные под актуальную угрозовую картину и регуляторные требования Российской Федерации.

## Состав

| Файл | Тип инцидента | Prefix | Регулятор |
|---|---|---|---|
| `ddos_hacktivism_ru.json` | DDoS-атака (хактивизм) | `[DDOS]` | НКЦКИ / 187-ФЗ |
| `apt_spearphishing_ru.json` | Целевой фишинг / APT | `[APT-FISH]` | НКЦКИ, ФСТЭК |
| `ransomware_ru.json` | Ransomware / Шифровальщик | `[RANS-RU]` | НКЦКИ / 187-ФЗ |
| `data_breach_ru.json` | Утечка данных / Data Breach | `[BREACH]` | РКН / 149-ФЗ, НКЦКИ |

## Импорт в DFIR-IRIS

1. Перейти в `Advanced → Case Templates`
2. Нажать `Import template`
3. Выбрать нужный `.json` файл
4. При создании кейса выбрать шаблон в поле `Case template`

## Регуляторный контекст

- **187-ФЗ (КИИ)** — уведомление НКЦКИ в течение **3 часов** с момента обнаружения инцидента
- **149-ФЗ / ПДн** — уведомление РКН: первичное — **24 часа**, расширенное — **72 часа**
- **ФСТЭК приказ № 235** — применяется для значимых объектов КИИ

## Покрытие TTPs (MITRE ATT&CK)

- Initial Access: Phishing (T1566), Valid Accounts (T1078)
- Execution: PowerShell (T1059.001), Scheduled Task (T1053)
- Lateral Movement: Pass-the-Hash (T1550.002), SMB/WMI
- Exfiltration: DNS Tunneling (T1071.004), HTTPS (T1048)
- Impact: Data Encrypted for Impact (T1486), Endpoint Denial of Service (T1499)
