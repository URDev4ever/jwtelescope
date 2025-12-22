<h1 align="center">JWTelescope</h1>
<p align="center">
  🇺🇸 <a href="README.md"><b>Inglés</b></a> |
  🇪🇸 <a href="README_ES.md">Español</a>
</p
<p align="center">
  <img width="1045" height="474" alt="jwtelescope" src="https://github.com/user-attachments/assets/4a0a435a-592e-4231-87f6-c49f5e3231a3" />
</p>

🔭 **JWTelescope** es una herramienta CLI avanzada para decodificar, inspeccionar y realizar análisis de seguridad sobre JSON Web Tokens (JWT). Está diseñada para **bug bounty hunters, pentesters y desarrolladores** que buscan obtener información rápida sobre la estructura de los JWT, sus *claims* y configuraciones incorrectas comunes.

La herramienta se centra en el **análisis de solo lectura** y en la **evaluación de riesgos**, lo que la hace segura para usar durante las fases de reconocimiento y *triage*.

---

## ✨ Características

* Decodificación del **header** y **payload** del JWT (Base64URL)
* Salida en terminal limpia, con colores y formato legible
* Detección automática de **problemas de seguridad comunes en JWT**
* Sistema de puntuación de riesgo: **Bajo / Medio / Alto**
* Conversión de timestamps a formato legible (`exp`, `iat`, `nbf`)
* Detección de patrones peligrosos:

  * `alg: none`
  * `exp` ausente o expirado
  * Tokens con una validez excesivamente larga
  * `aud` débil o genérico
  * Valores `kid` sospechosos (path traversal, predictibilidad)
  * Riesgo de confusión de algoritmo simétrico (HS256)
  * *Claims* personalizados peligrosos (`admin`, `role`, `scope`, etc.)
  * URLs externas en `jku` / `x5u`
* Salida **JSON estructurada** para reportes y automatización
* Modos compatibles con *pipes* (`--raw`, `--stdin`)
* Dependencias mínimas (solo librería estándar de Python)

---

## 🧠 Casos de uso

* Reconocimiento en bug bounty
* Detección de malas configuraciones en JWT
* Triage de tokens durante pruebas de APIs
* Reportes de seguridad (HackerOne / Bugcrowd)
* Aprendizaje y comprensión interna de JWT

---

## 📦 Instalación

Clona el repositorio:

```bash
git clone https://github.com/urdev4ever/jwtelescope.git
cd jwtelescope
```

Haz el script ejecutable (opcional):

```bash
chmod +x jwtelescope.py
```

Requisitos:

* Python **3.8+**
* No se requieren librerías externas

---

## 🚀 Uso

<img width="898" height="427" alt="jwtelescopehelp" src="https://github.com/user-attachments/assets/15dc281e-86b6-44cc-a344-a795241f6183" />

### Leer un JWT directamente

```bash
./jwtelescope.py -r "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Leer desde un archivo

```bash
./jwtelescope.py -f token.jwt
```

### Leer desde stdin (piping)

```bash
echo "JWT_TOKEN" | ./jwtelescope.py --stdin
```

### Salida JSON cruda (sin colores ni análisis)

```bash
./jwtelescope.py -r "JWT_TOKEN" --raw
```

### Mostrar solo advertencias de seguridad

```bash
./jwtelescope.py -r "JWT_TOKEN" --only-warnings
```

### Mostrar puntuación de riesgo

```bash
./jwtelescope.py -r "JWT_TOKEN" --score
```

### Generar reporte JSON estructurado

```bash
./jwtelescope.py -r "JWT_TOKEN" --json > report.json
```

<h5>[ ! ] Nota: solo puedes usar `./jwtelescope.py` si lo hiciste ejecutable; de lo contrario deberás usar:</h5>

```bash
python jwtelescope.py 
```

---

## 🧪 Ejemplo de salida (usando un JWT autorizado de anytask.com)

* Header decodificado

  <img width="431" height="177" alt="image (31)" src="https://github.com/user-attachments/assets/edca3371-2a6c-46ba-8c3f-3be0e987d4f5" />

* Payload decodificado

  <img width="355" height="502" alt="image (32)" src="https://github.com/user-attachments/assets/1851b20b-9cf1-493e-8d67-ba9b4985dbe1" />

* Detalles de la firma

  <img width="388" height="74" alt="image" src="https://github.com/user-attachments/assets/b4269c8c-bef3-48a3-9800-d477fc7aca9b" />

* Metadatos del token (longitud, algoritmo, key ID)

  <img width="202" height="92" alt="image" src="https://github.com/user-attachments/assets/ce5a1795-c0d8-4406-9d23-8691dba61733" />

* Resumen de *claims* comunes

  <img width="510" height="119" alt="image" src="https://github.com/user-attachments/assets/b76c421c-1d06-4ff7-89d4-c184ea2281f9" />

* Hallazgos de seguridad con severidad

  <img width="831" height="79" alt="image" src="https://github.com/user-attachments/assets/e5ee6788-0ad2-4a29-b7ed-adb6c8456d15" />

* Puntuación de riesgo general

  <img width="159" height="41" alt="image" src="https://github.com/user-attachments/assets/23651d36-dded-426e-bca8-fd3bd71d0879" />

---

## ⚠️ Lógica de puntuación de riesgo (simplificada)

| Problema                           | Severidad |
| ---------------------------------- | --------- |
| `alg: none`                        | Crítica   |
| `exp` ausente                      | Alta      |
| Token expirado                     | Alta      |
| Expiración > 10 años               | Alta      |
| `aud` débil                        | Media     |
| Riesgo de confusión HS256          | Media     |
| *Claims* personalizados peligrosos | Media     |
| `nbf` ausente                      | Baja      |

Niveles finales de riesgo:

* **Bajo**: Mayormente informativo
* **Medio**: Posible debilidad de seguridad
* **Alto**: Mala configuración probablemente explotable

---

## 📄 Estructura de salida JSON

```json
{
  "metadata": {},
  "token_info": {},
  "header": {},
  "payload": {},
  "security_analysis": {},
  "common_claims": {}
}
```

Diseñada para una integración sencilla en scripts, pipelines de CI o reportes.

---

## 🔒 Filosofía de seguridad

JWTelescope:

* **NO modifica tokens**
* **NO fuerza secretos**
* **NO evade autenticación**

Es una herramienta de **análisis pasivo**, pensada para pruebas de seguridad legítimas.

---

## ⭐ Descargo de responsabilidad

Esta herramienta está destinada **únicamente a fines educativos y pruebas de seguridad autorizadas**.
Prueba siempre contra sistemas que poseas o para los que tengas permiso explícito.

---

hecho con <3 por URDev
