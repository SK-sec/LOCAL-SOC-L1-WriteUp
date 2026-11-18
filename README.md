# Локальный стенд: Симуляция, детектирование и реагирование на веб-атаки (SOC L1)

Привет! В этом репозитории я собираю свои практические отчёты по симуляции веб-атак (OWASP Top 10) на локальном стенде, их расследованию через **Sysmon + Wazuh SIEM** и автоматическому сдерживанию с помощью **Shuffle SOAR**.

## 1. Архитектура стенда

Инфраструктура развёрнута на одном хосте и объединяет **WSL2** и виртуальную машину **Hyper-V**:

1. **Атакующий (`kali-linux`, WSL2)** — генерация вредоносного трафика и эксплуатация уязвимостей (`curl`).
2. **Жертва Linux (`victim`, WSL2)** — стек LAMP (Apache2 + MariaDB + PHP) с уязвимым приложением DVWA, агент Wazuh и Sysmon for Linux.
3. **Жертва Windows (`win-victim`, Hyper-V)** — Windows Server 2019 (Server Core), стек XAMPP (Apache + PHP) с DVWA, агент Wazuh и Windows Sysmon.
4. **Аналитика и реагирование (`analytics`, WSL2)** — Wazuh Manager (SIEM) для корреляции событий и Shuffle (SOAR) для автоматической изоляции угроз.

## 2. Список отчётов

### Linux-инфраструктура (Ubuntu / LAMP)
* **Отчёт №1:** [A03:2021 — Command Injection (Linux)](attacks/A03_Command_Injection_Lin.md)
  * *Ключевой фокус:* Скрытость POST-инъекций в `access.log`, перехват дочерних процессов через Sysmon for Linux (EventID 1) и автоматическая блокировка атакующего IP по Threat Intelligence через `iptables`.
* **Отчёт №2:** [A01:2021 — Broken Access Control / Web Shell (Linux)](attacks/A01_Broken_Access_Control_Lin.md)
  * *Ключевой фокус:* Детектирование загрузки бэкдора, тюнинг правил Wazuh по матрице MITRE ATT&CK (`T1505.003`) и карантин вредоносных файлов через Shuffle SOAR.

### Windows-инфраструктура (Windows Server 2019 / XAMPP)
* **Отчёт №3:** [A01:2021 — Broken Access Control / Web Shell (Windows)](attacks/A01_Broken_Access_Control_Win.md)
  * *Ключевой фокус:* Эксплуатация загрузки файлов в Windows с привилегиями `NT AUTHORITY\SYSTEM`, создание кастомного правила Wazuh (`100201`) поверх Sysmon и перемещение веб-шелла в карантин по SSH.
* **Отчёт №4:** [A03:2021 — Command Injection (Windows)](attacks/A03_Command_Injection_Win.md)
  * *Ключевой фокус:* Инъекция системных команд (`&`), анализ цепочки `httpd.exe -> cmd.exe` и автоматическая блокировка атакующего IP из Tor-фида в Windows Firewall.
