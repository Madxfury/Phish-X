"""Publish existing Flask assets at the same /static URLs on Vercel's CDN."""
from pathlib import Path
import shutil

if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    shutil.copytree(root / 'static', root / 'public' / 'static', dirs_exist_ok=True, ignore=shutil.ignore_patterns(".DS_Store", "._*"))
