# OWASP Top 10:2025 — Aplicaciones Web

Referencia oficial: https://owasp.org/Top10/2025/

OWASP (Open Worldwide Application Security Project) es una fundación y comunidad abierta sin fines de lucro dedicada a mejorar la seguridad del software. Este documento representa el release de concientización y referencia técnica para aplicaciones web. Cada categoría se estructura como un índice para profundizar en tres dimensiones clave: Contexto (el problema y su relevancia), CWEs (clases de debilidades asociadas) y Escenarios (manifestación práctica en arquitecturas reales).

## A01:2025 Broken Access Control

El control de acceso hace cumplir las políticas que impiden que los usuarios actúen fuera de sus permisos previstos. Las fallas en estos mecanismos permiten la divulgación no autorizada de información, la modificación o destrucción de datos, o la ejecución de funciones de negocio reservadas para roles privilegiados. La proliferación de microservicios, APIs expuestas y endpoints heredados incrementa drásticamente la superficie de ataque.

Las debilidades comunes asociadas corresponden a CWE-200 (Exposición de información sensible), CWE-284 (Control de acceso inadecuado), CWE-639 (Referencias directas a objetos inseguras o IDOR) y CWE-862 (Falta de autorización).

Un escenario típico ocurre cuando un usuario autenticado modifica un parámetro en la URL o en el cuerpo de una petición JSON (por ejemplo, alterando `account_id=105` por `account_id=106`) y la aplicación devuelve registros de otro cliente o tenant sin verificar la pertenencia del recurso en la capa de persistencia. Otro escenario involucra la navegación directa hacia rutas administrativas que carecen de middleware de autorización.

## A02:2025 Security Misconfiguration

La mala configuración de seguridad abarca configuraciones por defecto inseguras, configuraciones incompletas o ad-hoc, almacenamiento en la nube abierto, encabezados HTTP mal configurados y mensajes de error excesivamente detallados que exponen información del sistema. Es una de las fallas más comunes debido a la complejidad de las plataformas y servicios modernos.

Entre sus debilidades representativas se encuentran CWE-16 (Configuración de seguridad deficiente), CWE-209 (Generación de mensajes de error con información sensible) y CWE-1004 (Cookies sin atributo HttpOnly).

Un escenario frecuente es el despliegue de servidores de aplicaciones con consolas administrativas activadas bajo credenciales de fábrica. Otro caso ocurre cuando una excepción no controlada genera una respuesta HTTP 500 que incluye el stack trace completo de la base de datos, revelando rutas del sistema de archivos, nombres de tablas y versiones exactas de las librerías en ejecución.

## A03:2025 Software Supply Chain Failures

Esta categoría aborda los riesgos introducidos por la integración de dependencias de terceros, librerías de código abierto, contenedores base y herramientas del pipeline de integración y despliegue continuo (CI/CD). La confianza ciega en artefactos externos sin verificación de procedencia ni análisis continuo traslada vulnerabilidades directas a la aplicación final.

Se relaciona principalmente con CWE-1395 (Dependencia de componentes de terceros vulnerables), CWE-1104 (Uso de componentes no mantenidos) y CWE-829 (Inclusión de funcionalidad desde una esfera de control no confiable).

Un escenario de ataque implica el compromiso de un paquete popular en un repositorio público mediante técnicas de typosquatting o secuestro de cuentas de mantenedores, insertando código malicioso que se compila automáticamente en las imágenes de producción. Asimismo, no fijar las versiones exactas en manifiestos de dependencias expone al proyecto a roturas o vulnerabilidades no auditadas durante builds automatizados.

## A04:2025 Cryptographic Failures

Anteriormente conocida como exposición de datos sensibles, esta categoría se enfoca en deficiencias vinculadas al cifrado y a la protección de datos en tránsito y en reposo. Ocurre cuando no se implementa criptografía robusta, se emplean algoritmos obsoletos, se generan claves con entropía insuficiente o no se protegen adecuadamente secretos en memoria.

Incluye debilidades como CWE-259 (Uso de contraseñas hardcodeadas), CWE-319 (Transmisión en texto claro de información sensible), CWE-327 (Uso de algoritmo criptográfico roto o riesgoso) y CWE-330 (Uso de valores pseudoaleatorios insuficientemente seguros).

Un escenario habitual es el almacenamiento de credenciales o números de tarjetas de crédito en bases de datos utilizando funciones hash simples como MD5 o SHA-1 sin salt ni funciones de derivación lentas (como Argon2 o bcrypt). Otro caso es la omisión de TLS forzado con HSTS en APIs internas, permitiendo intercepciones en el tráfico mediante ataques Man-in-the-Middle.

## A05:2025 Injection

Las fallas de inyección ocurren cuando datos no confiables suministrados por un usuario o sistema externo son interpretados por un intérprete o motor de comandos como parte de una instrucción legítima. Esto permite eludir controles lógicos, alterar consultas a bases de datos o ejecutar comandos arbitrarios directamente en el sistema operativo del servidor.

Agrupa debilidades críticas como CWE-89 (Inyección SQL), CWE-78 (Inyección de comandos del sistema operativo), CWE-79 (Cross-Site Scripting - XSS) y CWE-94 (Inyección de código).

Un escenario habitual se produce cuando una aplicación web concatena parámetros de búsqueda directamente en una sentencia SQL sin utilizar consultas parametrizadas u ORMs seguros. Esto permite al atacante ingresar cadenas que alteran la lógica del query (por ejemplo, `' OR '1'='1`), volcando tablas enteras de usuarios y hashes de contraseñas.

## A06:2025 Insecure Design

El diseño inseguro refiere a la ausencia de controles y patrones de seguridad durante las etapas iniciales de arquitectura y modelado de amenazas, diferenciándose de las fallas de implementación en el código. Un sistema con diseño inseguro puede tener código perfectamente libre de bugs sintácticos, pero carecer de defensas conceptuales frente a vectores de ataque previsibles.

Se vincula con debilidades como CWE-657 (Violación de principios de diseño seguro) y CWE-1059 (Diseño con especificación de seguridad incompleta).

Los escenarios de manifestación incluyen la omisión de controles de frecuencia (rate limiting) en endpoints de compra o recuperación de contraseña, la falta de segregación estricta entre contextos multi-tenant a nivel de base de datos, o la creación de agentes con herramientas (tools) capaces de alterar o borrar recursos sin un flujo de confirmación explícito.

## A07:2025 Authentication Failures

Las fallas de autenticación abarcan problemas en la confirmación de la identidad del usuario, el manejo de credenciales y la administración del ciclo de vida de las sesiones. Permiten a atacantes comprometer contraseñas, tokens JWT o claves de API para suplantar identidades legítimas en el sistema.

Las debilidades más comunes son CWE-287 (Autenticación inapropiada), CWE-384 (Fijación de sesión), CWE-798 (Credenciales hardcodeadas) y CWE-307 (Restricción insuficiente de intentos excesivos de autenticación).

Un escenario recurrente es la susceptibilidad a ataques de fuerza bruta automatizados o credential stuffing debido a la falta de mecanismos de bloqueo de cuenta, captchas o autenticación multifactor (MFA). Otro caso crítico es la emisión de tokens de sesión con tiempos de expiración excesivamente largos o sin invalidación adecuada en el backend tras el cierre de sesión.

## A08:2025 Software or Data Integrity Failures

Esta categoría se centra en el código y la infraestructura que no protegen contra violaciones de integridad al procesar plugins, bibliotecas, actualizaciones o datos serializados provenientes de fuentes no verificadas. Confiar en la validez de objetos y archivos sin mecanismos criptográficos de verificación facilita la ejecución no autorizada de instrucciones.

Involucra debilidades como CWE-502 (Deserialización de datos no confiables) y CWE-494 (Descarga de código sin comprobación de integridad).

Un escenario clásico consiste en la deserialización directa de objetos enviados por el cliente en peticiones HTTP para reconstruir el estado de la sesión. Un atacante puede manipular la estructura binaria o JSON del objeto serializado para instanciar clases arbitrarias y forzar la ejecución remota de comandos (RCE) en el servidor.

## A09:2025 Security Logging and Alerting Failures

La insuficiencia en el registro de eventos, la monitorización deficiente y la falta de integración con sistemas de alerta impiden detectar incidentes de seguridad en tiempo real o realizar análisis forenses posteriores. Sin registros auditables, los atacantes pueden permanecer dentro de la infraestructura durante meses sin ser detectados.

Las debilidades principales son CWE-778 (Registro insuficiente) y CWE-117 (Neutralización incorrecta de salidas en logs o Log Injection).

Un escenario común se da cuando los intentos de inicio de sesión fallidos, los cambios de privilegios y las transacciones críticas no generan logs estructurados ni alertas en el SIEM. Asimismo, existe el riesgo opuesto de loguear información excesiva, como contraseñas en texto claro o datos de tarjetas de crédito (PII), violando normativas de privacidad.

## A10:2025 Mishandling of Exceptional Conditions

Esta categoría cubre el tratamiento deficiente de errores, excepciones y estados anómalos dentro de la lógica del sistema. Cuando las condiciones excepcionales no se gestionan de forma segura, la aplicación puede fallar en un estado abierto (fail-open), provocar denegaciones de servicio o exponer información crítica a través de respuestas inesperadas.

Sus debilidades asociadas incluyen CWE-755 (Manejo inadecuado de condiciones excepcionales) y CWE-754 (Verificación inadecuada de condiciones anómalas).

Un escenario frecuente ocurre cuando un bloque de manejo de errores captura excepciones genéricas y permite que el flujo de ejecución continúe asumiendo valores por defecto que eluden validaciones de seguridad previas. Otro caso es la caída completa del proceso del servidor al recibir una carga útil malformada que agota la memoria disponible.