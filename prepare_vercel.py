"""Keep the existing /static URLs served by Vercel's public CDN directory."""
from pathlib import Path
import shutil
import sys

if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    source, target = root / 'static', root / 'public' / 'static'
    if '--check' in sys.argv:
        assets = [p for p in source.rglob('*') if p.is_file() and p.name != '.DS_Store' and not p.name.startswith('._')]
        expected = {p.relative_to(source) for p in assets}
        actual = {p.relative_to(target) for p in target.rglob('*') if p.is_file() and p.name != '.DS_Store' and not p.name.startswith('._')}
        if expected != actual or any(not (target / p.relative_to(source)).is_file() or p.read_bytes() != (target / p.relative_to(source)).read_bytes() for p in assets):
            raise SystemExit('Public assets differ from static sources. Run python prepare_vercel.py and commit both.')
    else:
        shutil.copytree(source, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns('.DS_Store', '._*'))
