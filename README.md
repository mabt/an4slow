# an4slow

Analyseur de slow logs PHP-FPM. Identifie les modules tiers problematiques dans les installations **Magento 2**, **PrestaShop** et **WordPress**.

## Fonctionnalites

- Detection automatique du CMS (Magento, PrestaShop, WordPress)
- Identification des modules/extensions tiers responsables des ralentissements
- Classification des bottlenecks : MySQL, Redis I/O, HTTP/cURL, parsing, decompression
- Affichage des root causes et hot frames par module
- Detection des stacks recurrentes (signatures)
- Separation des composants infra (Redis, Credis) des modules applicatifs
- Filtrage automatique des modules core Magento
- Fusion intelligente des modules `generated/` avec leurs equivalents `vendor/`
- Sortie coloree dans le terminal

## Installation

### Binaire pre-compile

```bash
go build -o an4slow main.go
```

### Depuis les sources

```bash
go run main.go <fichier.log>
```

Aucune dependance externe. Go >= 1.18.

## Utilisation

```bash
# Analyse basique
./an4slow /var/log/php-fpm/www-slow.log

# Sans couleurs (pour redirection vers fichier)
./an4slow --no-color slow.log > rapport.txt

# Limiter le nombre de modules affiches
./an4slow --top 5 slow.log
```

## Exemple de sortie

```
======================================================================
  an4slow - PHP Slow Log Analysis Report
======================================================================

CMS detecte : MAGENTO
Entries analysees : 10

--- Types de bottleneck ---
  MySQL query             4 (40%) ####################
  Redis I/O               4 (40%) ####################
  HTTP/cURL               1 (10%) #####
  Parsing                 1 (10%) #####

--- Composants infra dans les slow logs ---
  colinmollenhour/cache-backend-redis: 4/10 (40%)
  colinmollenhour/credis: 4/10 (40%)

--- Top modules/extensions tiers ---

  #1 amasty/gdpr-cookie
      Apparitions: 4/10 (40%)
      Root causes:
        - [2x] execute() <- .../Pdo/Mysql.php:90
        - [2x] fetchRow() <- .../AbstractDb.php:333
      Hot frames:
        - [2x] getFlagData() .../CookieVersionControlService.php:57
        - [2x] getGroupData() .../SideBar.php:76

  #2 Amasty/Ogrid
      Apparitions: 1/10 (10%)
      ...

--- Stacks recurrentes (signatures) ---

  [2x] fgets() .../credis/Client.php:1483 -> read_reply() ...
  [2x] getFlagData() .../CookieVersionControlService.php:57 -> ...
======================================================================
```

## Format des slow logs

L'outil attend le format standard des slow logs PHP-FPM :

```
[29-Apr-2025 10:23:45]  [pool www] pid 12345
script_filename = /var/www/html/index.php
[0x00007f...] sleep() /path/to/file.php:42
[0x00007f...] someFunction() /path/to/other.php:100
```

Configurer PHP-FPM pour generer ces logs :

```ini
; php-fpm.conf ou pool.d/www.conf
request_slowlog_timeout = 3s
slowlog = /var/log/php-fpm/www-slow.log
```

## Licence

MIT
