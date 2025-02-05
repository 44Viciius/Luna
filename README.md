# Luna
Luna - Automated Security Scanner 🛡️

⚠️ Aviso legal
Este script es solo para fines educativos y pruebas de seguridad en entornos controlados. No lo uses sin autorización. El uso indebido es responsabilidad exclusiva del usuario.

Luna es una herramienta de pentesting automatizado diseñada para evaluar la seguridad de aplicaciones web mediante pruebas de SQL Injection, XSS y configuraciones de seguridad ausentes. Su objetivo es identificar vulnerabilidades rápidamente y generar reportes efectivos para mejorar la seguridad de los sistemas.

🚀 Características
🔎 Exploración automática de vulnerabilidades en URLs especificadas.
🛠️ Pruebas de SQL Injection con payloads personalizados.
💀 Detección de XSS para evaluar la exposición a ataques de scripting.
🔐 Análisis de encabezados de seguridad como HSTS.
⚡ Integración con APIs y endpoints web.

🎯 Uso básico

python luna.py <URL> --param <nombre_parametro> --valid_value <valor> --invalid_value <valor> --weak_token <token> --sql_payloads "<payloads>" --xss_payloads "<payloads>"

Ejemplo: 
python luna.py https://example.com/login --param user --valid_value admin --invalid_value hacker --weak_token "secrettoken" --sql_payloads "' OR 1=1 --" --xss_payloads "<script>alert('XSS')</script>"

🛠️ Instalación
📌 Requisitos previos
Antes de ejecutar Luna, asegúrate de tener instalado:
Python 3.8+
pip (administrador de paquetes de Python)





