"""Verificador independiente del anclaje semanal de evidencia (§3.9, nivel 2).

Comprueba que un fichero de anclaje publicado por el sistema (serializado por
``serializar_anclaje``: claves ``version_formato``, ``semana``, ``algoritmo``,
``raiz_merkle``, ``instante``, ``hojas``) es íntegro: que la raíz de Merkle
publicada se deriva exactamente de las hojas que lo acompañan.

Uso::

    python herramientas/verificar_anclaje.py <ruta_al_fichero.json>

Este script es **autónomo y no depende del sistema**: usa solo la biblioteca
estándar de Python y **reimplementa por sí mismo** el algoritmo
``sha256-merkle-v1``, sin importar el paquete ``precios``. Esa independencia es
deliberada: un tercero puede auditar el archivo histórico de precios sin instalar
ni confiar en nuestro código, recomputando la raíz con esta utilidad mínima y
comparándola con la que se publicó.

Algoritmo ``sha256-merkle-v1`` (reimplementado aquí, no copiado):

1. Hojas := hashes únicos, ordenados ascendentemente como texto hex.
2. Cada hoja se decodifica a sus 32 bytes; las hojas no se vuelven a hashear.
3. Nivel a nivel, cada par consecutivo produce ``SHA-256(izquierdo ∥ derecho)``
   sobre los 32 + 32 bytes; un nodo impar sube sin cambios (no se duplica).
4. La raíz es el único nodo del último nivel, en hex. Con una sola hoja, la raíz
   es la propia hoja.

Códigos de salida: ``0`` si el anclaje se verifica; ``1`` si no se verifica, el
algoritmo es desconocido, el fichero no existe, no es JSON válido o le faltan los
campos esperados.
"""

import hashlib
import json
import sys
from pathlib import Path
from typing import cast

# Único algoritmo que este verificador sabe reproducir. Un nombre distinto se
# rechaza: no podemos certificar lo que no sabemos recomputar.
_ALGORITMO_SOPORTADO = "sha256-merkle-v1"


def _raiz_merkle(hojas: list[str]) -> str:
    """Pliega las hojas (hex de 32 bytes) hasta la raíz de Merkle, en hex.

    Reimplementación independiente de ``sha256-merkle-v1``: deduplica y ordena las
    hojas como texto hex, las decodifica a bytes y pliega nivel a nivel emparejando
    consecutivos con ``SHA-256(izquierdo ∥ derecho)``; un nodo impar sube sin
    duplicarse. Con una sola hoja, la raíz es esa misma hoja.
    """
    hojas_canonicas = sorted(set(hojas))
    nivel: list[bytes] = [bytes.fromhex(hoja) for hoja in hojas_canonicas]
    while len(nivel) > 1:
        siguiente: list[bytes] = [
            hashlib.sha256(nivel[i] + nivel[i + 1]).digest()
            for i in range(0, len(nivel) - 1, 2)
        ]
        if len(nivel) % 2 == 1:
            siguiente.append(nivel[-1])
        nivel = siguiente
    return nivel[0].hex()


def _texto(datos: dict[str, object], clave: str) -> str | None:
    """Devuelve ``datos[clave]`` si es un ``str``; ``None`` si falta o no lo es."""
    valor = datos.get(clave)
    return valor if isinstance(valor, str) else None


def _lista_de_hojas(datos: dict[str, object]) -> list[str] | None:
    """Devuelve ``datos['hojas']`` si es una lista de ``str``; si no, ``None``."""
    valor = datos.get("hojas")
    if not isinstance(valor, list):
        return None
    # ``isinstance`` solo prueba que es una lista; sus elementos son ``object`` hasta
    # que el bucle los valide uno a uno. El ``cast`` documenta ese tipo sin inventar
    # garantías (no afirma str: eso lo comprueba el ``isinstance`` de cada elemento).
    lista = cast(list[object], valor)
    hojas: list[str] = []
    for elemento in lista:
        if not isinstance(elemento, str):
            return None
        hojas.append(elemento)
    return hojas


def verificar(datos: dict[str, object]) -> tuple[bool, str]:
    """Verifica un anclaje ya parseado; devuelve ``(ok, mensaje_legible)``.

    Valida que el ``algoritmo`` sea el soportado, que ``raiz_merkle`` y ``hojas``
    tengan el tipo esperado, recomputa la raíz desde las hojas y la compara con la
    publicada. ``ok`` es ``True`` solo si todo cuadra; el mensaje describe el
    resultado (``VERIFICADO`` / ``FALLO`` y el motivo) para imprimirlo al auditor.
    """
    algoritmo = _texto(datos, "algoritmo")
    if algoritmo != _ALGORITMO_SOPORTADO:
        return False, (
            f"FALLO: algoritmo desconocido {algoritmo!r}; "
            f"este verificador solo reproduce {_ALGORITMO_SOPORTADO!r}."
        )

    raiz_publicada = _texto(datos, "raiz_merkle")
    if raiz_publicada is None:
        return False, "FALLO: el campo 'raiz_merkle' falta o no es una cadena."

    hojas = _lista_de_hojas(datos)
    if hojas is None:
        return False, "FALLO: el campo 'hojas' falta o no es una lista de cadenas."
    if not hojas:
        return False, "FALLO: el anclaje no tiene hojas; no hay raíz que recomputar."

    semana = _texto(datos, "semana") or "(semana desconocida)"

    try:
        raiz_calculada = _raiz_merkle(hojas)
    except ValueError as error:
        return False, f"FALLO: una hoja no es hex válido de 32 bytes: {error}."

    if raiz_calculada != raiz_publicada:
        return False, (
            f"FALLO: la raíz recomputada {raiz_calculada} no coincide con la "
            f"publicada {raiz_publicada} (semana {semana})."
        )

    return True, f"VERIFICADO: semana {semana}, raíz {raiz_publicada}."


def main(argv: list[str]) -> int:
    """Verifica el fichero de anclaje indicado; devuelve el código de salida.

    ``argv`` es la lista de argumentos sin el nombre del programa (``sys.argv[1:]``);
    espera un único argumento posicional: la ruta al fichero JSON del anclaje. Errores
    de uso, de E/S o de formato van a stderr con código ``1``; un anclaje que no
    verifica imprime ``FALLO`` y devuelve ``1``; uno íntegro imprime ``VERIFICADO`` a
    stdout y devuelve ``0``.
    """
    if len(argv) != 1:
        print(
            "Uso: python herramientas/verificar_anclaje.py <fichero.json>",
            file=sys.stderr,
        )
        return 1

    ruta = Path(argv[0])
    try:
        texto = ruta.read_text(encoding="utf-8")
    except OSError as error:
        print(f"No se pudo leer el fichero {ruta}: {error}", file=sys.stderr)
        return 1

    try:
        parseado: object = json.loads(texto)
    except json.JSONDecodeError as error:
        print(f"El fichero {ruta} no es JSON válido: {error}", file=sys.stderr)
        return 1

    if not isinstance(parseado, dict):
        print(
            f"El fichero {ruta} no contiene un objeto JSON de anclaje.",
            file=sys.stderr,
        )
        return 1

    # ``json.loads`` sobre un objeto da ``dict`` con claves str y valores arbitrarios;
    # el ``cast`` fija ese tipo (``verificar`` valida luego cada campo por separado).
    datos = cast(dict[str, object], parseado)
    ok, mensaje = verificar(datos)
    if ok:
        print(mensaje)
        return 0

    # Algoritmo desconocido o cualquier campo inválido: el motivo va a stderr (es un
    # error de entrada, no un veredicto sobre hojas íntegras). Un desajuste de raíz
    # también imprime FALLO a stderr; en ambos casos el código es 1.
    print(mensaje, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
