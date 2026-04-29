from pathlib import Path
from typing import Optional

from .models import YaraMatch

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

DEFAULT_RULES_DIR = Path(__file__).parent.parent / "signatures" / "yara"


class YaraScanner:
    def __init__(self, rules_dir: Optional[Path] = None):
        self._rules: Optional[object] = None
        self._rules_dir = rules_dir or DEFAULT_RULES_DIR

    def _load_rules(self) -> None:
        if not YARA_AVAILABLE:
            return
        if not self._rules_dir.exists():
            return

        rule_files = {
            p.stem: str(p)
            for p in self._rules_dir.rglob("*.yar")
        }
        rule_files.update({
            p.stem: str(p)
            for p in self._rules_dir.rglob("*.yara")
        })

        if not rule_files:
            return

        try:
            self._rules = yara.compile(filepaths=rule_files)
        except yara.SyntaxError as e:
            raise RuntimeError(f"YARA rule compile error: {e}") from e

    @property
    def rules(self):
        if self._rules is None:
            self._load_rules()
        return self._rules

    def scan_file(self, file_path: str | Path) -> list[YaraMatch]:
        if not YARA_AVAILABLE or self.rules is None:
            return []

        try:
            matches = self.rules.match(str(file_path))
        except Exception:
            return []

        results = []
        for match in matches:
            results.append(YaraMatch(
                rule_name=match.rule,
                tags=list(match.tags),
                meta=dict(match.meta),
                strings=[(s.instances[0].offset, s.identifier, s.instances[0].matched_data)
                         for s in match.strings if s.instances],
            ))
        return results


_default_scanner = YaraScanner()


def scan_with_yara(file_path: str | Path) -> list[YaraMatch]:
    return _default_scanner.scan_file(file_path)
