"""Builds the Mythaia website: one page per language from template.html and i18n/<lang>.json.

    python site/build.py --version 1.1.2 --out _site

The version fills the download links. Images come from docs/assets, so the site and the README
show the same files. Standard library only: the Pages workflow runs it on a bare runner.
"""
import argparse
import html
import json
import re
import shutil
from pathlib import Path

SITE = Path(__file__).resolve().parent
ROOT = SITE.parent
URL = "https://myth-t0ks1k.github.io/Mythaia/"
REPO = "https://github.com/Myth-T0ks1k/Mythaia"

# (code, folder, hreflang). English is the root page.
LANGUAGES = [
    ("en", "", "en"),
    ("ru", "ru/", "ru"),
    ("tk", "tk/", "tk"),
    ("zh", "zh/", "zh-CN"),
    ("fa", "fa/", "fa"),
]

ASSETS = {
    "docs/assets/logo.svg": "logo.svg",
    "docs/assets/social-preview.png": "social-preview.png",
    "docs/assets/screenshots/home.png": "screens/home.png",
    "docs/assets/screenshots/proxies.png": "screens/proxies.png",
    "docs/assets/screenshots/add-fronting.png": "screens/add-fronting.png",
    "docs/assets/screenshots/settings.png": "screens/settings.png",
    "site/static/site.css": "site.css",
    "site/static/site.js": "site.js",
}


def downloads(version):
    base = f"{REPO}/releases/download/v{version}/"
    return {
        "dl_universal": base + f"Mythaia-{version}-android-universal.apk",
        "dl_arm64": base + f"Mythaia-{version}-android-arm64-v8a.apk",
        "dl_wear": base + f"Mythaia-{version}-wear-os.apk",
        "dl_setup": base + f"Mythaia-Pro-{version}-windows-x64-setup.exe",
        "dl_msi": base + f"Mythaia-Pro-{version}-windows-x64.msi",
        "dl_portable": base + f"Mythaia-Pro-{version}-windows-x64-portable.zip",
        "dl_sums": base + "SHA256SUMS.txt",
    }


def render(template, values, strings):
    """{{t.key}} takes a translation (trusted HTML), {{key}} a computed value."""
    def sub(match):
        key = match.group(1)
        if key.startswith("t."):
            name = key[2:]
            if name not in strings:
                raise KeyError(f"missing translation {name!r}")
            return strings[name]
        if key not in values:
            raise KeyError(f"missing value {key!r}")
        return values[key]

    # Translations may hold {{version}} themselves, so resolve twice.
    once = re.sub(r"\{\{([a-z0-9_.]+)\}\}", sub, template)
    return re.sub(r"\{\{([a-z0-9_.]+)\}\}", sub, once)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", default="_site")
    args = parser.parse_args()
    version = args.version.lstrip("v")
    out = Path(args.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    (out / "assets" / "screens").mkdir(parents=True)

    for src, dst in ASSETS.items():
        shutil.copyfile(ROOT / src, out / "assets" / dst)
    (out / ".nojekyll").write_text("")

    template = (SITE / "template.html").read_text(encoding="utf-8")
    english = json.loads((SITE / "i18n" / "en.json").read_text(encoding="utf-8"))
    all_strings = {}
    for code, _, _ in LANGUAGES:
        strings = json.loads((SITE / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
        missing = sorted(set(english) - set(strings))
        if missing:
            raise SystemExit(f"{code}.json lacks {missing}")
        all_strings[code] = strings

    hreflang = "\n".join(
        f'<link rel="alternate" hreflang="{tag}" href="{URL}{folder}">' for _, folder, tag in LANGUAGES
    ) + f'\n<link rel="alternate" hreflang="x-default" href="{URL}">'

    for code, folder, tag in LANGUAGES:
        strings = all_strings[code]
        base = "../" if folder else ""
        lang_links = "\n".join(
            f'<li><a href="{base}{f}" hreflang="{t}" lang="{t}" data-lang="{c}"'
            f'{" aria-current=\"page\"" if c == code else ""}>{all_strings[c]["lang_name"]}</a></li>'
            for c, f, t in LANGUAGES
        )
        app = {
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            "name": "Mythaia",
            "applicationCategory": "UtilitiesApplication",
            "operatingSystem": "Android, Windows",
            "softwareVersion": version,
            "description": html.unescape(re.sub(r"<[^>]+>", "", strings["meta_description"])),
            "url": URL + folder,
            "downloadUrl": f"{REPO}/releases/latest",
            "license": "https://www.gnu.org/licenses/gpl-3.0.html",
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        }
        values = {
            "lang": tag,
            "code": code,
            "dir": "rtl" if code == "fa" else "ltr",
            "base": base,
            "url": URL + folder,
            "site": URL,
            "repo": REPO,
            "version": version,
            "hreflang": hreflang,
            "lang_links": lang_links,
            "jsonld": json.dumps(app, ensure_ascii=False),
            **downloads(version),
        }
        page = render(template, values, strings)
        target = out / folder / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(page, encoding="utf-8")
        print("built", target.relative_to(out))

    notfound = render(
        (SITE / "404.html").read_text(encoding="utf-8"),
        {"site": URL, "base": URL},
        english,
    )
    (out / "404.html").write_text(notfound, encoding="utf-8")

    entries = []
    for _, folder, _ in LANGUAGES:
        links = "".join(
            f'<xhtml:link rel="alternate" hreflang="{t}" href="{URL}{f}"/>' for _, f, t in LANGUAGES
        )
        entries.append(f"<url><loc>{URL}{folder}</loc>{links}</url>")
    (out / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
        'xmlns:xhtml="http://www.w3.org/1999/xhtml">' + "".join(entries) + "</urlset>\n",
        encoding="utf-8",
    )
    (out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {URL}sitemap.xml\n")
    print("version", version)


if __name__ == "__main__":
    main()
