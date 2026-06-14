# Anclajes públicos de «Histórico de precios de supermercado»

Este repositorio es el **canal público de anclaje semanal** (Nivel 2 de la evidencia
auditable) del proyecto experimental *Histórico de precios de supermercado*. Cada semana
en la que se capturaron precios, el sistema publica aquí un fichero que permite a
**cualquier tercero demostrar criptográficamente** que una observación de precio existía
en el sistema esa semana, sin necesidad de confiar en nosotros ni de tener acceso al
sistema.

El sello que lo hace inmutable es el propio historial de commits de GitHub: cada anclaje
es un commit con la fecha del servidor, fuera de nuestro control.

## Qué hay en cada fichero

Un anclaje por semana ISO, en `anclajes/<año>-W<semana>.json`. Ejemplo:

```json
{
  "version_formato": 1,
  "semana": "2026-W24",
  "algoritmo": "sha256-merkle-v1",
  "raiz_merkle": "37559302956dfbf0faa4045c5f564d6b726058497e11de3a5adf49e84789511f",
  "instante": "2026-06-14T06:35:00.764771+00:00",
  "hojas": [
    "48df2efb5d770e829a4d418df208cc25310d32201392dfe5519f9240f82c6819",
    "9981d4ce93cd55b3a929187ec6a495a1fada08349754a47ec1fed2bfa2d272b7",
    "d8f309e0bec43aa6d61c991efa9554405e9a04b3fdf418db11a1d318b0993a78"
  ]
}
```

| Campo | Significado |
|---|---|
| `version_formato` | Versión del formato de este fichero (entero). Si cambia, cambia el número. |
| `semana` | Semana ISO 8601 `año-Wsemana`, con fronteras evaluadas en UTC. |
| `algoritmo` | Nombre versionado del algoritmo del árbol, p. ej. `sha256-merkle-v1`. |
| `raiz_merkle` | Raíz del árbol de Merkle (SHA-256 en hex). |
| `instante` | Cuándo se construyó el anclaje (informativo; no entra en el cálculo). |
| `hojas` | Los `payload_hash` (SHA-256 del sobre de evidencia de cada observación) de la semana, en orden canónico. |

## Cómo verificarlo (sin instalar nada del proyecto)

El cálculo se reproduce con `verificar_anclaje.py`, un script **autónomo de solo librería
estándar de Python 3** (no importa el paquete del proyecto). Recalcula la raíz desde las
hojas publicadas y la compara con `raiz_merkle`:

```bash
python3 verificar_anclaje.py anclajes/2026-W24.json
```

Salida esperada cuando el anclaje es íntegro:

```
VERIFICADO: semana 2026-W24, raíz 37559302956dfbf0...
```

Devuelve código de salida `0` si la raíz coincide; distinto de `0` (con `FALLO` o el
motivo) si no coincide, si el algoritmo es desconocido o si el fichero está corrupto.

## El algoritmo `sha256-merkle-v1`

Lo que `verificar_anclaje.py` reproduce, paso a paso:

1. **Hojas**: los hashes únicos, ordenados ascendentemente como texto hexadecimal.
2. Cada hoja se decodifica a sus 32 bytes; las hojas **no** se vuelven a hashear (ya son
   el SHA-256 del sobre de evidencia).
3. Nivel a nivel, cada par consecutivo produce un padre `SHA-256(izquierdo ∥ derecho)`
   (concatenación de los 32 + 32 bytes). Si un nivel tiene un nodo impar, ese nodo
   **sube sin cambios** al nivel siguiente (no se duplica).
4. La **raíz** es el único nodo del último nivel, en hex. Con una sola hoja, la raíz es la
   propia hoja.

Para verificar además una **observación concreta**, se necesita su sobre de evidencia
(el payload bruto que devolvió la fuente): se recalcula su SHA-256, se comprueba que está
entre las `hojas` de la semana, y que esas hojas producen la `raiz_merkle` anclada.
