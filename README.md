# PW User Geo 🌍

A lightweight WordPress plugin to detect a visitor’s country using a **local MaxMind GeoLite2-Country** database (no external API calls).  
Includes optional **geolocation-based redirect rules** and **cache-safe front-end display** via shortcodes or helper functions.

---

## 🧰 Features

✅ Detects user location (country & ISO code) using `GeoLite2-Country.mmdb`  
✅ Works fully **offline** (no API requests)  
✅ Caches results per IP to improve performance  
✅ Admin settings page for country → URL redirect rules  
✅ Supports “skip for logged-in/admin users” and `?geo_noredirect=1` bypass  
✅ Shortcodes and PHP functions for showing country or triggering redirect  
✅ AJAX and JS-based output to avoid cache issues  

---

## 📦 Installation

1. Copy the plugin folder to:  wp-content/plugins/pw-user-geo/
2. Activate it from **WordPress → Plugins**.
3. Download the latest [GeoLite2-Country.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)  
and place it inside the plugin folder.
4. (Optional) Run composer in the plugin folder to install dependencies: composer require geoip2/geoip2:^2.13

⚙️ Admin Settings

Go to Settings → PW User Geo Redirects

You can define redirect rules in this format:

IL|https://he.webdevtest.co.il{REQUEST_URI}
FR|https://fr.webdevtest.co.il{REQUEST_URI}
ES|https://es.webdevtest.co.il{REQUEST_URI}
DE|https://de.webdevtest.co.il{REQUEST_URI}
*|https://webdevtest.co.il{REQUEST_URI}


Notes:

CC = Country ISO code (e.g., IL, FR, US, etc.)

{REQUEST_URI} will be replaced with the current page path

Use * as fallback for all other countries

🧩 Shortcodes & PHP Functions
Display the visitor’s country

Shortcode:
[pw_user_country label="Detecting…"]

PHP function:
echo pw_user_geo_country_html('Loading country...');

Trigger redirect by user country

Shortcode:
[pw_user_geo_redirect]

PHP:
echo pw_user_geo_redirect_html();

🚀 Debugging Tips

Visit Tools → PW User Geo to check detected IP & country.

Append ?pw_geo_ip=8.8.8.8 to override IP manually (for testing).

Append ?pw_geo_flush=1 to clear IP cache.

Append ?geo_noredirect=1 to disable redirect (sets cookie).

🧠 Requirements

PHP 7.4+ (tested up to PHP 8.3)

WordPress 6.0+

MaxMind GeoLite2-Country database

geoip2/geoip2 Composer package

👨‍💻 Author

Yaniv Sasson
WordPress Developer — https://yanivsasson.co.il

📄 License

GPL-2.0+
This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com


---

Would you like me to create a **`README.md` file ready to copy** into your plugin folder (with Markdown formatting and emoji icons preserved)?  
I can generate and format it exactly for GitHub preview.
