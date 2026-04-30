# an4slow

PHP-FPM and MySQL slow log analyzer. Identifies problematic third-party modules in **Magento 2**, **PrestaShop** and **WordPress** installations.

## Features

- Automatic CMS detection (Magento, PrestaShop, WordPress)
- Identification of third-party modules/extensions causing slowdowns
- Bottleneck classification: MySQL, Redis I/O, HTTP/cURL, parsing, decompression
- **Severity score** per module (weighted by bottleneck type)
- **Hourly distribution** of slow logs to identify peaks
- **Context breakdown**: frontend, admin, cron/cli, API
- **Blocking HTTP call detection** in observers/plugins
- **MySQL slow log analysis** with query fingerprinting
- **PHP-FPM / MySQL correlation**: temporal matching, hourly peaks, module-to-table mapping
- Root causes and hot frames per module
- Recurring stack signatures
- Infrastructure component separation (Redis, Credis, OpenSearch, Elasticsearch)
- Automatic core module filtering (Magento, PrestaShop, WordPress)
- Smart merging of `generated/` modules with their `vendor/` equivalents
- Colored terminal output

## Installation

### Download binary (Linux x86_64)

```bash
curl -sL https://github.com/mabt/an4slow/releases/latest/download/an4slow -o /usr/local/bin/an4slow && chmod +x /usr/local/bin/an4slow
```

### Build from source

```bash
go build -o an4slow main.go
```

No external dependencies. Go >= 1.18.

## Usage

```bash
# Basic analysis (auto-detects MySQL slow log at /var/log/mysql/mysql-slow.log)
./an4slow /var/log/php-fpm/www-slow.log

# Custom MySQL slow log path
./an4slow --mysql-log /path/to/mysql-slow.log /var/log/php-fpm/www-slow.log

# Disable MySQL slow log analysis
./an4slow --no-mysql slow.log

# No colors (for file redirection)
./an4slow --no-color slow.log > report.txt

# Limit number of modules displayed
./an4slow --top 5 slow.log
```

## Example output

```
======================================================================
  an4slow - PHP Slow Log Analysis Report
======================================================================

CMS detecte : MAGENTO
Entries analysees : 5108
Periode : 29-Apr-2026 00:00:12 -> 29-Apr-2026 16:45:50

--- Repartition par contexte ---
  frontend                4820 (94%)
  cron/cli                 230 ( 4%)
  admin                     58 ( 1%)

--- Distribution horaire ---
  09h  312 ▓▓▓▓▓▓▓▓▓▓▓
  10h  890 ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
  11h  720 ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
  ...

--- Types de bottleneck ---
  Redis I/O            3079 (60%) ##############################
  MySQL query           782 (15%) #######
  HTTP/cURL             130 ( 2%) #

--- Appels HTTP bloquants dans observers/plugins ---
  [40x] Citytech/Configurations
       processProductForStore() .../Observer/ProductSaveAfter.php:87

--- Top modules/extensions tiers (par severite) ---

  #1 Citytech/Configurations [score: 853]
      Apparitions: 53/5108 (1%)
      Root causes:
        - [40x] curl_exec() <- .../YounitedClient.php:197

  #2 amasty/label [score: 2483]
      Apparitions: 710/5108 (13%)
      ...

======================================================================
  MySQL Slow Log Analysis
======================================================================

Requetes lentes : 234
Temps cumule : 1842.3s
Temps moyen : 7.873s

--- Top requetes lentes (par temps cumule) ---

  #1 [12x, cumul: 340.2s, max: 45.3s, avg: 28.350s]
      Rows examined (avg): 1234567  Rows sent (avg): 1
      SELECT * FROM catalog_product_entity WHERE entity_id IN (...)

======================================================================
  Correlations PHP-FPM / MySQL
======================================================================

--- Modules avec requetes MySQL correlees ---

  Mageplaza/DailyDeal (86x MySQL, cumul: 124.5s)
      Tables: mp_dailydeal (34x), catalog_product_entity (28x)
      Requete type: SELECT * FROM mp_dailydeal WHERE product_id IN (...)

--- Pics horaires correles ---

  Heure      PHP    MySQL
  10h        890      156  ← pic simultane
  11h        720      134  ← pic simultane
======================================================================
```

## Slow log format

The tool expects the standard PHP-FPM slow log format:

```
[29-Apr-2025 10:23:45]  [pool www] pid 12345
script_filename = /var/www/html/index.php
[0x00007f...] sleep() /path/to/file.php:42
[0x00007f...] someFunction() /path/to/other.php:100
```

Configure PHP-FPM to generate these logs:

```ini
; php-fpm.conf or pool.d/www.conf
request_slowlog_timeout = 3s
slowlog = /var/log/php-fpm/www-slow.log
```

For MySQL slow log, enable it in your MySQL configuration:

```ini
; /etc/mysql/mysql.conf.d/mysqld.cnf
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 1
```

## License

MIT
