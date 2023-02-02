Stop russian war. **🇺🇦 Free Ukraine!**

# sentry

This is a fork. I think it works. DSN JS not yet implemented.

![Screenshot](images/sentry.png?raw=true)

**This new version is fully incompatible with previous ones.**

Run the following queries to update and delete old configuration values:
```sql
UPDATE core_config_data SET path = REPLACE(path, "/amg-sentry/", "/sentry/") WHERE path LIKE "%/amg-sentry/%";
UPDATE core_config_data SET path = REPLACE(path, "-", "_") WHERE path LIKE "%/sentry/%";
UPDATE core_config_data SET path = "dev/sentry/dsn_js_front" WHERE path LIKE "dev/sentry/dsn_js";
DELETE FROM core_config_data WHERE path LIKE "dev/sentry/php_errors";
DELETE FROM core_config_data WHERE path LIKE "dev/sentry/php_exceptions";
DELETE FROM core_config_data WHERE path LIKE "dev/sentry/ignore_error_control_operator";
DELETE FROM core_config_data WHERE path LIKE "dev/sentry/%" AND path NOT LIKE "dev/sentry/logger"
  AND path NOT LIKE "dev/sentry/dsn_js_front" AND scope_id != 0;
```

To install:
- run `composer require luigifab/openmage-sentry`
- apply `openmage.diff` or `openmage-more.diff`
- apply `errors.diff`

For configuration, go to: `System / Configuration / Developer / Sentry`.

- Current version: 2.0.0 (02/02/2023)
- Compatibility: OpenMage 19.x / 20.x / 21.x, PHP 7.2 / 7.3 / 7.4 / 8.0 / 8.1 / 8.2
- License: OSL 3.0

If you like, take some of your time to improve some translations, go to https://bit.ly/2HyCCEc.
