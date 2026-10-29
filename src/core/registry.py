"""Registro local de módulos do núcleo."""

from threading import RLock
from typing import TypeVar


ModuleT = TypeVar("ModuleT")


class ModuleRegistry:
    def __init__(self) -> None:
        self._lock = RLock()
        self._modules: dict[str, object] = {}

    def register(self, name: str, module: ModuleT) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("O nome do módulo deve ser uma string não vazia.")
        if module is None:
            raise ValueError("Não é possível registrar um módulo None.")
        normalized_name = name.strip()
        with self._lock:
            if normalized_name in self._modules:
                raise ValueError(f"Módulo já registrado: {normalized_name}.")
            self._modules[normalized_name] = module

    def get(self, name: str) -> object:
        normalized_name = name.strip() if isinstance(name, str) else name
        with self._lock:
            try:
                return self._modules[normalized_name]
            except KeyError as error:
                raise KeyError(f"Módulo não registrado: {normalized_name}.") from error

    def unregister(self, name: str) -> object:
        normalized_name = name.strip() if isinstance(name, str) else name
        with self._lock:
            try:
                return self._modules.pop(normalized_name)
            except KeyError as error:
                raise KeyError(f"Módulo não registrado: {normalized_name}.") from error

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._modules)
