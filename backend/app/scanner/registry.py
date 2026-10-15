"""Check registry for managing scanner checks deterministically."""

import re

from app.scanner.check import BaseCheck, CheckMetadata


class RegistryError(Exception):
    """Base exception for check registry errors."""


class DuplicateCheckIdError(RegistryError):
    """Raised when registering a check with an ID that is already registered."""


class InvalidCheckError(RegistryError):
    """Raised when an object does not properly implement the BaseCheck interface."""


class CheckNotFoundError(RegistryError):
    """Raised when a requested check ID does not exist in the registry."""


CHECK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,99}$")


class CheckRegistry:
    """Central registry maintaining valid scanner check instances in deterministic order."""

    def __init__(self):
        self._checks: dict[str, BaseCheck] = {}

    def register(self, check: BaseCheck | type[BaseCheck]) -> None:
        """Register a check instance or class.

        Validates interface compliance, ID syntax, and duplicate prevention.
        """
        instance: BaseCheck
        if isinstance(check, type):
            if not issubclass(check, BaseCheck):
                raise InvalidCheckError(f"Class '{check.__name__}' must inherit from BaseCheck")
            try:
                instance = check()
            except Exception as exc:
                raise InvalidCheckError(
                    f"Could not instantiate check class '{check.__name__}': {exc}"
                ) from exc
        elif isinstance(check, BaseCheck):
            instance = check
        else:
            raise InvalidCheckError(
                f"Expected instance or subclass of BaseCheck, received {type(check).__name__}"
            )

        # Validate metadata
        try:
            meta = instance.metadata
            if not isinstance(meta, CheckMetadata):
                raise InvalidCheckError(
                    f"Check metadata must be an instance of CheckMetadata, got {type(meta)}"
                )
        except Exception as exc:
            raise InvalidCheckError(f"Failed to access valid check metadata: {exc}") from exc

        check_id = meta.check_id
        if not CHECK_ID_PATTERN.match(check_id):
            raise InvalidCheckError(
                f"Check ID '{check_id}' is invalid. Must match pattern {CHECK_ID_PATTERN.pattern}"
            )

        if check_id in self._checks:
            raise DuplicateCheckIdError(
                f"Check with ID '{check_id}' is already registered in this registry"
            )

        self._checks[check_id] = instance

    def get(self, check_id: str) -> BaseCheck:
        """Retrieve a registered check by its unique check_id."""
        if check_id not in self._checks:
            raise CheckNotFoundError(f"Check '{check_id}' not found in registry")
        return self._checks[check_id]

    def list_checks(self) -> list[BaseCheck]:
        """Return all registered checks sorted deterministically by check_id."""
        return [self._checks[cid] for cid in sorted(self._checks.keys())]

    def list_check_ids(self) -> list[str]:
        """Return all registered check IDs sorted alphabetically."""
        return sorted(self._checks.keys())

    def unregister(self, check_id: str) -> None:
        """Remove a check from the registry if present."""
        self._checks.pop(check_id, None)

    def clear(self) -> None:
        """Clear all registered checks."""
        self._checks.clear()

    def __len__(self) -> int:
        return len(self._checks)

    def __contains__(self, check_id: str) -> bool:
        return check_id in self._checks


# Global default registry instance
default_registry = CheckRegistry()
