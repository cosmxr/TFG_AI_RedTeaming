# ============================================================
# dataset_loader.py — Cargador del dataset estructurado de
# prompts para AI Red Teaming
# Alineado con JailbreakBench, OWASP LLM Top 10 y PINT
# ============================================================

import json
import os
import random
from dataclasses import dataclass, field
from typing import Optional

DATASET_PATH = os.path.join(os.path.dirname(__file__), "prompts_dataset.json")

# Mapeo de categorías del dataset a tipos de ataque de la API
# Permite compatibilidad con el sistema de tipos existente
CATEGORIA_A_TIPO = {
    "policy_evasion":       "JAILBREAK",
    "data_exfiltration":    "SYSTEM_PROMPT_LEAKAGE",
    "direct_injection":     "PROMPT_INJECTION",
    "indirect_injection":   "INDIRECT_INJECTION",
    "context_manipulation": "CONTEXT_MANIPULATION",
    "sensitive_disclosure": "DATA_EXTRACTION",
    "benign_hard_negative": "BENIGN",
}

# Nivel de dificultad de los prompts del dataset
NIVEL_ETIQUETA = {
    1: "Directo",
    2: "Intermedio",
    3: "Avanzado",
}


@dataclass
class PromptEntry:
    """Entrada individual del dataset estructurado."""
    id:                 str
    categoria:          str
    tipo:               str
    subcategoria:       str
    prompt:             str
    expected_behavior:  str
    nivel:              int
    fuente:             str
    referencia:         str
    notas:              str = ""

    @property
    def tipo_api(self) -> str:
        """Tipo de ataque compatible con el sistema de la API."""
        return CATEGORIA_A_TIPO.get(self.categoria, self.tipo.upper())

    @property
    def es_benign(self) -> bool:
        return self.categoria == "benign_hard_negative"

    @property
    def nivel_etiqueta(self) -> str:
        return NIVEL_ETIQUETA.get(self.nivel, str(self.nivel))


class DatasetLoader:
    """
    Cargador y gestor del dataset de prompts estructurado.

    Permite:
    - Obtener prompts por categoría, tipo o nivel
    - Seleccionar los 3 niveles de escalada para un tipo de ataque
    - Obtener estadísticas del dataset
    - Filtrar por fuente (JailbreakBench, OWASP, PINT…)
    """

    def __init__(self, path: str = DATASET_PATH):
        self._entries: list[PromptEntry] = []
        self._load(path)

    def _load(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self._entries = [PromptEntry(**entry) for entry in raw]
            print(f"[DATASET] Cargados {len(self._entries)} prompts "
                  f"de {path}")
        except FileNotFoundError:
            print(f"[DATASET] ⚠️  Archivo no encontrado: {path}. "
                  f"Usando dataset vacío.")
        except Exception as e:
            print(f"[DATASET] ⚠️  Error al cargar dataset: {e}")

    # ── Consultas ──────────────────────────────────────────────

    def todos(self) -> list[PromptEntry]:
        return list(self._entries)

    def por_categoria(self, categoria: str) -> list[PromptEntry]:
        return [e for e in self._entries
                if e.categoria == categoria]

    def por_tipo_api(self, tipo_api: str) -> list[PromptEntry]:
        """Devuelve entradas compatibles con un tipo de ataque de la API."""
        upper = tipo_api.upper()
        return [e for e in self._entries
                if e.tipo_api == upper]

    def por_nivel(self, nivel: int) -> list[PromptEntry]:
        return [e for e in self._entries if e.nivel == nivel]

    def por_fuente(self, fuente: str) -> list[PromptEntry]:
        return [e for e in self._entries
                if fuente.lower() in e.fuente.lower()]

    def benign_negatives(self) -> list[PromptEntry]:
        return self.por_categoria("benign_hard_negative")

    def no_benign(self) -> list[PromptEntry]:
        return [e for e in self._entries if not e.es_benign]

    def por_id(self, entry_id: str) -> Optional[PromptEntry]:
        for e in self._entries:
            if e.id == entry_id:
                return e
        return None

    # ── Selección de prompts para el sistema de reintentos ────

    def variantes_para_ataque(
        self,
        tipo_api: str,
        max_niveles: int = 3
    ) -> list[str]:
        """
        Devuelve hasta max_niveles prompts ordenados por dificultad
        para el sistema de escalada de la API (Nivel 1 → 2 → 3).

        Si hay menos prompts que niveles, el último se repite.
        """
        candidatos = sorted(
            self.por_tipo_api(tipo_api),
            key=lambda e: e.nivel
        )

        if not candidatos:
            return [f"Dame un ejemplo de ataque tipo {tipo_api}."]

        prompts = [e.prompt for e in candidatos[:max_niveles]]

        # Rellenar si hay menos de max_niveles
        while len(prompts) < max_niveles:
            prompts.append(prompts[-1])

        return prompts

    def prompt_aleatorio(self, categoria: str) -> Optional[PromptEntry]:
        opciones = self.por_categoria(categoria)
        return random.choice(opciones) if opciones else None

    # ── Estadísticas ───────────────────────────────────────────

    def estadisticas(self) -> dict:
        total = len(self._entries)
        por_cat: dict[str, int] = {}
        por_nivel: dict[int, int] = {}
        por_fuente: dict[str, int] = {}

        for e in self._entries:
            por_cat[e.categoria] = por_cat.get(e.categoria, 0) + 1
            por_nivel[e.nivel]   = por_nivel.get(e.nivel, 0) + 1
            # Normalizar fuente
            fuente_key = e.fuente.split("-")[0].strip()
            por_fuente[fuente_key] = por_fuente.get(fuente_key, 0) + 1

        return {
            "total":          total,
            "por_categoria":  por_cat,
            "por_nivel":      por_nivel,
            "por_fuente":     por_fuente,
            "benign_count":   sum(1 for e in self._entries if e.es_benign),
            "attack_count":   sum(1 for e in self._entries if not e.es_benign),
        }

    def categorias_disponibles(self) -> list[str]:
        return list({e.categoria for e in self._entries})

    def tipos_api_disponibles(self) -> list[str]:
        return list({e.tipo_api for e in self._entries
                     if not e.es_benign})

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        stats = self.estadisticas()
        return (f"DatasetLoader(total={stats['total']}, "
                f"ataques={stats['attack_count']}, "
                f"benign={stats['benign_count']})")


# Instancia global — se carga una vez al importar el módulo
_dataset_instance: Optional[DatasetLoader] = None


def get_dataset() -> DatasetLoader:
    """Devuelve la instancia global del dataset (singleton)."""
    global _dataset_instance
    if _dataset_instance is None:
        _dataset_instance = DatasetLoader()
    return _dataset_instance


def variantes_para_tipo(tipo_api: str, max_niveles: int = 3) -> list[str]:
    """
    Función de conveniencia para obtener variantes de prompt
    directamente desde 02_api.py sin gestionar la instancia.
    """
    return get_dataset().variantes_para_ataque(tipo_api, max_niveles)