# OWASP Top Riesgos para LLMs (2025)

Este documento detalla los principales riesgos de seguridad al implementar Inteligencia Artificial y Modelos de Lenguaje Grande (LLMs) en aplicaciones. A diferencia de los sistemas tradicionales, el LLM es una dependencia más: la seguridad vive en la separación de identidad, contexto, acciones, modelo, evaluación y monitoreo.

## LLM01:2025 Prompt Injection

Consiste en la manipulación del modelo mediante prompts maliciosos (directa o indirecta). Esta manipulación directa e indirecta de las instrucciones del sistema busca forzar comportamientos no autorizados o saltar filtros de seguridad. 

Un riesgo crítico en RAG ocurre si indexás documentos que no controlás del todo (contenido de usuarios, PDFs de terceros). Un atacante puede insertar instrucciones maliciosas dentro de esos documentos que el LLM seguirá cuando ese chunk se recupere como contexto. Para mitigarlo, es clave no dar tools (herramientas) amplias y validar siempre la intención y el contexto.

## LLM02:2025 Sensitive Information Disclosure

Implica la filtración involuntaria de datos sensibles, PII (Información de Identificación Personal), secretos o información corporativa. Esto incluye la filtración de claves API y tokens en código cliente, o datos confidenciales expuestos en prompts o en un entrenamiento no protegido del modelo. La regla de diseño fundamental es no filtrar secrets en prompts, logs ni responses.

## LLM03:2025 Supply Chain Vulnerabilities

Ataques dirigidos a componentes externos del ecosistema de IA, lo que incluye modelos de terceros, datasets utilizados, plugins o proveedores de infraestructura.

## LLM04:2025 Data and Model Poisoning

Contaminación intencionada de los datos de entrenamiento, los procesos de fine-tuning o el almacenamiento de datos utilizado para RAG.

## LLM05:2025 Improper Output Handling (Insecure Output)

Este riesgo surge por la falta de validación del output generado por el modelo. La premisa de seguridad es clara: la salida del LLM no es confiable solo porque parece bien redactada. Aceptar respuestas generadas por la IA sin sanitización previa puede derivar en ataques como XSS, ejecución remota de código (RCE) o SSRF.

Un caso típico ocurre cuando el LLM genera HTML, SQL, código, comandos o JSON que otra parte del sistema ejecuta o renderiza. Esto genera el riesgo de inyección, comandos peligrosos, decisiones erróneas o bypass de validaciones. El control adecuado exige escapar, sanitizar, validar schema, usar allowlists y no ejecutar sin política. Siempre se debe validar la salida antes de ejecutar o guardar.

## LLM06:2025 Excessive Agency

Ocurre cuando el LLM actúa con demasiada autonomía sin controles adecuados. Para mitigar este riesgo, la arquitectura debe implementar permisos estrictos por tool (herramienta), definir scopes de autorización, requerir pruebas en seco (dry-run) y solicitar aprobaciones (approvals) humanas para acciones destructivas.

## LLM07:2025 System Prompt Leakage

Consiste en la exposición de las instrucciones internas (system prompt) mediante ataques diseñados para extraer las reglas fundacionales del modelo.

## LLM08:2025 Vector and Embedding Weaknesses

Vulnerabilidades que residen en las bases vectoriales y los embeddings utilizados típicamente en sistemas RAG. El escenario más crítico es el "Data leakage entre usuarios". Si el vector store mezcla documentos de distintos usuarios o tenants sin aislar el retrieval, una consulta puede traer de vuelta información que no le correspondía ver a quien preguntó.

## LLM09:2025 Misinformation / Hallucinations

Generación de información falsa con un potencial impacto negativo en las decisiones de los usuarios o del sistema. Una mitigación principal en arquitecturas RAG es citar fuentes, lo que ayuda a revisar si la respuesta se basa en documentos correctos.

## LLM10:2025 Unbounded Consumption

Consumo excesivo de recursos computacionales o económicos (costos) que puede derivar en ataques de denegación de servicio (DoS), provocado intencionalmente mediante prompts maliciosos o cargas pesadas.