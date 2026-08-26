# OWASP API Security Top 10:2023

Esta es la edición oficial y estable del proyecto API Security. Se centra en los riesgos propios de objetos, flujos, cuotas e inventario. Elegir esta referencia correcta, en lugar del Top 10 Web, evita mezclar niveles de seguridad

La exposición de información en APIs es un efecto transversal y no una sola categoría. Puede resultar de acceso roto, configuración insegura, fallos criptográficos o manejo incorrecto de errores. La causa es la que determina el control, y el remedio general implica cambiar la arquitectura, el requisito o el flujo, además de corregir código y pruebas.

## API1:2023 Broken Object Level Authorization
Pertenece a la familia de errores de "Autorización". Se caracteriza por un control insuficiente por objeto, propiedad o función. Uno de los errores más importantes en APIs ocurre cuando la API valida el token, pero no verifica si ese usuario tiene permisos para acceder a un objeto específico (por ejemplo, acceder a la factura 12345 con el token de otro usuario). El control requiere validar el ownership o tenant.

## API2:2023 Broken Authentication
Pertenece al Top 10 de riesgos en APIs, enfocado en problemas de autenticación.

## API3:2023 Broken Object Property Level Authorization
Pertenece a la familia de errores de "Autorización", implicando un control insuficiente. Es una referencia frecuente en casos de exposición de información, la cual suele verse como campos excesivos en respuestas, documentación pública o datos sin cifrado.

## API4:2023 Unrestricted Resource Consumption
Pertenece a la familia de errores de "Límites y negocio". Ocurre cuando un sistema funciona sin cuotas establecidas o sin protección en sus flujos sensibles.

## API5:2023 Broken Function Level Authorization
Pertenece a la familia de errores de "Autorización". Consiste en un control insuficiente a nivel de objeto, propiedad o función

## API6:2023 Unrestricted Access to Sensitive Business Flows
Pertenece a la familia de errores de "Límites y negocio". Se genera por la falta de cuotas o de protección adecuada en los flujos sensibles de la aplicación

## API7:2023 Server Side Request Forgery
Pertenece a la familia de errores relacionados a "Terceros y datos" Ocurre al confiar en URLs o respuestas externas sin validarlas previamente.

## API8:2023 Security Misconfiguration
Pertenece a la familia de errores de "Superficie expuesta". Se relaciona con una configuración débil, versiones olvidadas o el modo debug activo. Es una causa frecuente de exposición de información, manifestándose en stack traces expuestos o endpoints antiguos

## API9:2023 Improper Inventory Management
Pertenece a la familia de errores de "Superficie expuesta", vinculada a versiones olvidadas o configuraciones débiles. Al igual que API3 y API8, es una referencia frecuente que deriva en la exposición de información

## API10:2023 Unsafe Consumption of APIs
Pertenece a la familia de errores de "Terceros y datos". El riesgo radica en confiar en URLs o respuestas externas sin aplicar las validaciones correspondientes.