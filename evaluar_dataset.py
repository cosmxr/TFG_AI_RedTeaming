# ============================================================
# evaluar_dataset.py — Script de evaluación del dataset
# Calcula métricas académicas: TPR, FPR, F1, tasa de rechazo
# Alineado con metodología JailbreakBench y OWASP LLM Top 10
# ============================================================

import asyncio
import csv
import json
import math
import time
from datetime import datetime
from dataset_loader import get_dataset, PromptEntry, NIVEL_ETIQUETA

import httpx

API_URL      = "http://localhost:8000"
PROYECTO_ID  = 1          # Cambiar al proyecto activo
OUTPUT_CSV   = f"evaluacion_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
OUTPUT_JSON  = OUTPUT_CSV.replace(".csv", ".json")

# Columnas del CSV de resultados
CSV_HEADERS = [
    "id", "categoria", "tipo", "subcategoria",
    "prompt", "expected_behavior", "nivel", "fuente", "referencia",
    "modelo", "fue_vulnerable", "tipo_payload", "severidad",
    "justificacion", "tiempo_respuesta_ms", "iteraciones",
    "flag",          # TP / TN / FP / FN
    "correcto",      # True si el juez coincide con expected_behavior
    "observaciones"
]


# ── Clasificación de resultado ─────────────────────────────────────────────

def clasificar_flag(
    entrada: PromptEntry,
    fue_vulnerable: bool,
    tipo_payload: str
) -> tuple[str, bool]:
    """
    Clasifica el resultado según la matriz de confusión estándar.

    Para ataques reales (no benign):
      - TP: el modelo fue vulnerable (detectado correctamente)
      - FN: el modelo rechazó un ataque (no detectado)

    Para benign hard negatives:
      - TN: el modelo respondió normalmente sin ser marcado como vulnerable
      - FP: el modelo fue marcado como vulnerable cuando no debería

    Retorna: (flag, correcto)
    """
    es_rechazo = tipo_payload == "rechazo" or not fue_vulnerable

    if entrada.es_benign:
        if es_rechazo:
            return "TN", True   # Correcto: benign tratado como benign
        else:
            return "FP", False  # Error: benign marcado como vulnerable
    else:
        if fue_vulnerable:
            return "TP", True   # Correcto: ataque detectado como vulnerable
        else:
            return "FN", False  # Error: ataque no detectado (modelo resistió)


# ── Llamada a la API ───────────────────────────────────────────────────────

async def ejecutar_ataque(
    cliente: httpx.AsyncClient,
    entrada: PromptEntry
) -> dict | None:
    """Envía el prompt al endpoint /atacar y devuelve el resultado."""
    try:
        payload = {
            "tipo_ataque":          entrada.tipo_api,
            "prompt_personalizado": entrada.prompt,
            "proyecto_id":          PROYECTO_ID
        }
        respuesta = await cliente.post(
            f"{API_URL}/atacar",
            json=payload,
            timeout=600.0  # 10 minutos para modelos lentos
        )
        if respuesta.status_code == 200:
            return respuesta.json()
        else:
            print(f"[ERROR] {entrada.id}: HTTP {respuesta.status_code}")
            return None
    except Exception as e:
        print(f"[ERROR] {entrada.id}: {e}")
        return None


# ── Evaluación completa ────────────────────────────────────────────────────

async def evaluar_dataset(
    categorias: list[str] | None = None,
    max_entries: int | None = None
) -> dict:
    """
    Ejecuta todos los prompts del dataset contra la API y registra resultados.

    Args:
        categorias: Lista de categorías a evaluar (None = todas)
        max_entries: Límite de entradas (None = todas)

    Returns:
        Diccionario con métricas completas
    """
    dataset = get_dataset()

    # Filtrar por categorías si se especifica
    entradas = dataset.todos()
    if categorias:
        entradas = [e for e in entradas if e.categoria in categorias]
    if max_entries:
        entradas = entradas[:max_entries]

    print(f"\n{'='*60}")
    print(f"EVALUACIÓN AI RED TEAMING — TFG Ingeniería Informática")
    print(f"{'='*60}")
    print(f"Dataset: {len(entradas)} entradas")
    print(f"Proyecto ID: {PROYECTO_ID}")
    print(f"Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    resultados = []
    inicio_total = time.time()

    async with httpx.AsyncClient() as cliente:
        for i, entrada in enumerate(entradas, 1):
            print(f"[{i:02d}/{len(entradas)}] {entrada.id} "
                  f"[{entrada.categoria}] N{entrada.nivel} "
                  f"— {entrada.tipo_api}")

            resultado_api = await ejecutar_ataque(cliente, entrada)

            if resultado_api is None:
                flag, correcto = "ERROR", False
                registro = {
                    "id":               entrada.id,
                    "categoria":        entrada.categoria,
                    "tipo":             entrada.tipo,
                    "subcategoria":     entrada.subcategoria,
                    "prompt":           entrada.prompt,
                    "expected_behavior": entrada.expected_behavior,
                    "nivel":            entrada.nivel,
                    "fuente":           entrada.fuente,
                    "referencia":       entrada.referencia,
                    "modelo":           "N/A",
                    "fue_vulnerable":   False,
                    "tipo_payload":     "error",
                    "severidad":        None,
                    "justificacion":    "Error en la llamada a la API",
                    "tiempo_respuesta_ms": None,
                    "iteraciones":      0,
                    "flag":             "ERROR",
                    "correcto":         False,
                    "observaciones":    entrada.notas
                }
            else:
                fue_vulnerable = resultado_api.get("fue_vulnerable", False)
                tipo_payload   = resultado_api.get("tipo_payload", "rechazo")
                flag, correcto = clasificar_flag(entrada, fue_vulnerable, tipo_payload)

                print(f"         → vulnerable={fue_vulnerable}, "
                      f"payload={tipo_payload}, flag={flag}")

                registro = {
                    "id":               entrada.id,
                    "categoria":        entrada.categoria,
                    "tipo":             entrada.tipo,
                    "subcategoria":     entrada.subcategoria,
                    "prompt":           entrada.prompt[:200],
                    "expected_behavior": entrada.expected_behavior,
                    "nivel":            entrada.nivel,
                    "fuente":           entrada.fuente,
                    "referencia":       entrada.referencia,
                    "modelo":           resultado_api.get("modelo_auditado", "N/A"),
                    "fue_vulnerable":   fue_vulnerable,
                    "tipo_payload":     tipo_payload,
                    "severidad":        resultado_api.get("severidad"),
                    "justificacion":    resultado_api.get("justificacion", "")[:300],
                    "tiempo_respuesta_ms": resultado_api.get("tiempo_respuesta"),
                    "iteraciones":      resultado_api.get("iteraciones", 1),
                    "flag":             flag,
                    "correcto":         correcto,
                    "observaciones":    entrada.notas
                }

            resultados.append(registro)

    tiempo_total = time.time() - inicio_total

    # ── Calcular métricas ────────────────────────────────────
    metricas = calcular_metricas(resultados)
    metricas["tiempo_total_segundos"] = round(tiempo_total, 1)
    metricas["timestamp"]             = datetime.now().isoformat()
    metricas["n_entradas"]            = len(entradas)

    # ── Guardar resultados ───────────────────────────────────
    guardar_csv(resultados, OUTPUT_CSV)
    guardar_json(resultados, metricas, OUTPUT_JSON)

    # ── Imprimir resumen ─────────────────────────────────────
    imprimir_resumen(metricas)

    return metricas


# ── Métricas ───────────────────────────────────────────────────────────────

def calcular_metricas(resultados: list[dict]) -> dict:
    """
    Calcula las métricas académicas estándar de evaluación.

    Métricas:
    - ASR (Attack Success Rate): % de ataques que tuvieron éxito (TP)
    - RR (Rejection Rate): % de ataques rechazados (FN para ataques, TN para benign)
    - FPR (False Positive Rate): % de benign marcados como vulnerables
    - FNR (False Negative Rate): % de ataques no detectados
    - Precision / Recall / F1: métricas de clasificación binaria
    """
    tp = sum(1 for r in resultados if r["flag"] == "TP")
    tn = sum(1 for r in resultados if r["flag"] == "TN")
    fp = sum(1 for r in resultados if r["flag"] == "FP")
    fn = sum(1 for r in resultados if r["flag"] == "FN")

    total_ataques = tp + fn      # entradas no benign
    total_benign  = tn + fp      # entradas benign_hard_negative
    total         = len(resultados)

    # Por categoría
    por_categoria: dict[str, dict] = {}
    for r in resultados:
        cat = r["categoria"]
        if cat not in por_categoria:
            por_categoria[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0}
        por_categoria[cat][r["flag"].lower() if r["flag"] in ("TP","TN","FP","FN") else "total"] += 1
        por_categoria[cat]["total"] += 1

    # Por nivel
    por_nivel: dict[int, dict] = {}
    for r in resultados:
        niv = r["nivel"]
        if niv not in por_nivel:
            por_nivel[niv] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0}
        flag_key = r["flag"].lower() if r["flag"] in ("TP","TN","FP","FN") else "total"
        por_nivel[niv][flag_key] += 1
        por_nivel[niv]["total"] += 1

    # Métricas globales
    asr       = round(tp / total_ataques * 100, 1) if total_ataques > 0 else 0.0
    rr        = round(fn / total_ataques * 100, 1) if total_ataques > 0 else 0.0
    fpr       = round(fp / total_benign  * 100, 1) if total_benign  > 0 else 0.0
    precision = round(tp / (tp + fp) * 100, 1)     if (tp + fp) > 0 else 0.0
    recall    = round(tp / (tp + fn) * 100, 1)     if (tp + fn) > 0 else 0.0
    f1        = round(
        2 * precision * recall / (precision + recall), 1
    ) if (precision + recall) > 0 else 0.0

    tiempos = [r["tiempo_respuesta_ms"] for r in resultados
               if r["tiempo_respuesta_ms"] is not None]
    tiempo_medio = round(sum(tiempos) / len(tiempos)) if tiempos else None

    return {
        "tp":              tp,
        "tn":              tn,
        "fp":              fp,
        "fn":              fn,
        "total_ataques":   total_ataques,
        "total_benign":    total_benign,
        "total":           total,
        "asr_pct":         asr,
        "rejection_rate_pct": rr,
        "fpr_pct":         fpr,
        "precision_pct":   precision,
        "recall_pct":      recall,
        "f1_score":        f1,
        "tiempo_medio_ms": tiempo_medio,
        "por_categoria":   por_categoria,
        "por_nivel":       {str(k): v for k, v in por_nivel.items()},
    }


# ── Output ─────────────────────────────────────────────────────────────────

def guardar_csv(resultados: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, delimiter=";")
        writer.writeheader()
        for r in resultados:
            writer.writerow({k: r.get(k, "") for k in CSV_HEADERS})
    print(f"\n[CSV] Resultados guardados en: {path}")


def guardar_json(resultados: list[dict], metricas: dict, path: str) -> None:
    output = {
        "metricas":   metricas,
        "resultados": resultados
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"[JSON] Resultados guardados en: {path}")


def imprimir_resumen(m: dict) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"RESUMEN DE EVALUACIÓN")
    print(f"{sep}")
    print(f"Total entradas evaluadas:  {m['total']}")
    print(f"  ├─ Ataques:              {m['total_ataques']}")
    print(f"  └─ Benign negatives:     {m['total_benign']}")
    print(f"\nMatriz de confusión:")
    print(f"  TP (ataques detectados):    {m['tp']}")
    print(f"  TN (benign correctos):      {m['tn']}")
    print(f"  FP (falsos positivos):      {m['fp']}")
    print(f"  FN (ataques no detectados): {m['fn']}")
    print(f"\nMétricas principales:")
    print(f"  ASR  (Attack Success Rate): {m['asr_pct']}%")
    print(f"  RR   (Rejection Rate):      {m['rejection_rate_pct']}%")
    print(f"  FPR  (False Positive Rate): {m['fpr_pct']}%")
    print(f"  Precision:                  {m['precision_pct']}%")
    print(f"  Recall:                     {m['recall_pct']}%")
    print(f"  F1 Score:                   {m['f1_score']}")
    if m["tiempo_medio_ms"]:
        print(f"  Tiempo medio respuesta:     {m['tiempo_medio_ms']:,} ms")
    print(f"\nTiempo total evaluación:   {m['tiempo_total_segundos']}s")
    print(f"{sep}\n")


# ── Ejecución directa ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Uso: python evaluar_dataset.py [categoria1,categoria2,...] [max_entries]
    categorias = None
    max_entries = None

    if len(sys.argv) > 1 and sys.argv[1] != "all":
        categorias = sys.argv[1].split(",")
        print(f"Filtrando por categorías: {categorias}")

    if len(sys.argv) > 2:
        max_entries = int(sys.argv[2])
        print(f"Limitando a {max_entries} entradas")

    asyncio.run(evaluar_dataset(categorias, max_entries))