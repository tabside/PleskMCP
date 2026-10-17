#!/usr/bin/env python3
"""Builds the AI-Hosting pages of the website in the site's own design (header, footer, meta from snippets/).

Usage: python3 build/pages.py <output root>   (e.g. the checkout of the website repository)
The pages reference the signup service at SIGNUP_BASE (env), default placeholder https://mcp.example.com/plesk.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SNIP = os.path.join(HERE, "..", "snippets")
SIGNUP_BASE = os.environ.get("SIGNUP_BASE", "https://mcp.example.com/plesk")


def snippet(name: str) -> str:
    with open(os.path.join(SNIP, name), encoding="utf-8") as fh:
        return fh.read()


def page(*, title: str, description: str, path: str, body: str, robots: str = "", head_extra: str = "", current: bool = False) -> str:
    meta = snippet("_meta.html").replace("__TITLE__", title).replace("__DESCRIPTION__", description).replace("__PATH__", path)
    meta = meta.replace("__ROBOTS__\n", f'<meta name="robots" content="{robots}">\n' if robots else "")
    header = snippet("_header.html").replace("__CURRENT__", ' aria-current="page"' if current else "")
    return (
        '<!DOCTYPE html>\n<html lang="de">\n<head>\n' + meta + head_extra + '</head>\n<body>\n' + snippet("_gtm_body.html") + "\n" + header
        + '<main id="content">\n' + body + '</main>\n' + snippet("_footer.html") + "</body>\n</html>\n"
    )


FORM_CSS = """<style>
.order{max-width:720px}
.order fieldset{border:1px solid var(--blue-soft);padding:24px 28px 8px;margin:0 0 32px}
.order legend{color:var(--white);font-weight:400;padding:0 8px}
.order .grid{display:grid;grid-template-columns:1fr 1fr;gap:0 24px}
.order select{width:100%;background:var(--bg);border:0;border-bottom:1px solid var(--text);color:var(--white);font:inherit;padding:12px 14px}
.order select:focus{outline:1px solid var(--blue);outline-offset:2px}
.order .choice label{display:flex;gap:10px;align-items:center;font-size:1rem;color:var(--white);margin:0 0 10px}
.order .choice input{width:auto;margin:0}
.order .hint{font-size:.85rem;color:var(--muted);margin:0 0 .8em}
.order .error{color:#F6A5A5;font-size:.85rem;min-height:1.2em;margin:4px 0 0}
.order .error-box{border:1px solid #B14C4C;color:#F6A5A5;padding:12px 16px;margin:0 0 24px}
.order .availability{font-size:.95rem;min-height:1.4em;margin:6px 0 0}
.order .availability.free{color:#9FE3B4}
.order .availability.taken{color:#F6A5A5}
.order .summary{border:1px solid var(--blue-soft);background:rgba(41,87,203,.06);padding:20px 24px;margin:0 0 28px}
.order .summary table{width:100%;border-collapse:collapse}
.order .summary td{padding:6px 0;border-bottom:1px solid var(--blue-soft)}
.order .summary td:last-child{text-align:right;white-space:nowrap;color:var(--white)}
.order .summary tr.total td{border-bottom:0;color:var(--white);font-weight:400;padding-top:12px}
.order label.terms{display:flex;gap:10px;align-items:flex-start;font-size:.95rem;color:var(--text)}
.order label.terms input{width:auto;margin-top:5px}
.order .btn[disabled]{opacity:.6;cursor:wait}
@media(max-width:600px){.order .grid{grid-template-columns:1fr}}
</style>
"""

ORDER_BODY = """<section class="hero" style="padding:110px 0 24px"><div class="wrap"><div class="inner" style="max-width:760px">
<h1 style="font-weight:200">AI Hosting bestellen</h1>
<p class="lead">Nach der Bestellung bestätigen Sie Ihre E-Mail-Adresse per Link, dann erhalten Sie die Rechnung per E-Mail (QR-Rechnung oder Kreditkarte). Sobald die Zahlung eingegangen ist, wird Ihr Hosting automatisch freigeschaltet und Sie erhalten die Zugangsdaten und die Anleitung für den KI-Zugang.</p>
</div></div></section>
<section style="padding-top:24px"><div class="wrap order">
<div class="error-box" id="aih-error" hidden></div>
<form id="aih-order" method="post" action="__SIGNUP_BASE__/signup" novalidate>
<input type="hidden" name="token" value="">
<div class="hp" aria-hidden="true"><label>Bitte leer lassen<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>

<fieldset>
<legend>Domain</legend>
<div class="choice">
<label><input type="radio" name="domain_mode" value="own" checked> Ich habe bereits eine Domain</label>
<label><input type="radio" name="domain_mode" value="new" id="aih-mode-new"> Neue Domain registrieren</label>
</div>
<div class="field"><label for="domain">Domainname</label><input id="domain" name="domain" type="text" required autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="meine-firma.ch">
<div class="error" data-error-for="domain"></div><div class="availability" id="aih-availability"></div></div>
<p class="hint" id="aih-own-hint">Ihre Domain bleibt bei Ihrem bisherigen Anbieter. Nach der Freischaltung stellen Sie dort die Nameserver oder den A-Record auf das neue Hosting um; die Angaben stehen in der Willkommensmail.</p>
<p class="hint" id="aih-new-hint">Online bestellbare Endungen: <span id="aih-tld-list">werden geladen …</span>. Andere Endungen auf Anfrage über das <a href="/kontakt/">Kontaktformular</a>.</p>
<div class="error" data-error-for="domain_mode"></div>
</fieldset>

<fieldset>
<legend>Rechnungsadresse</legend>
<div class="field"><label for="company">Firma (optional)</label><input id="company" name="company" type="text" maxlength="100" autocomplete="organization"><div class="error" data-error-for="company"></div></div>
<div class="grid">
<div class="field"><label for="first_name">Vorname</label><input id="first_name" name="first_name" type="text" required maxlength="60" autocomplete="given-name"><div class="error" data-error-for="first_name"></div></div>
<div class="field"><label for="last_name">Name</label><input id="last_name" name="last_name" type="text" required maxlength="60" autocomplete="family-name"><div class="error" data-error-for="last_name"></div></div>
</div>
<div class="field"><label for="street">Strasse und Nr.</label><input id="street" name="street" type="text" required maxlength="120" autocomplete="street-address"><div class="error" data-error-for="street"></div></div>
<div class="grid">
<div class="field"><label for="zip">PLZ</label><input id="zip" name="zip" type="text" required maxlength="16" autocomplete="postal-code"><div class="error" data-error-for="zip"></div></div>
<div class="field"><label for="city">Ort</label><input id="city" name="city" type="text" required maxlength="60" autocomplete="address-level2"><div class="error" data-error-for="city"></div></div>
</div>
<div class="field"><label for="country">Land</label><select id="country" name="country" required autocomplete="country"><option value="CH">Schweiz</option></select><div class="error" data-error-for="country"></div></div>
<div class="field"><label for="email">E-Mail (für Rechnung und Zugangsdaten)</label><input id="email" name="email" type="email" required maxlength="254" autocomplete="email"><div class="error" data-error-for="email"></div></div>
<div class="field"><label for="phone" id="aih-phone-label">Telefon (optional)</label><input id="phone" name="phone" type="tel" maxlength="32" autocomplete="tel" placeholder="+41 61 123 45 67"><div class="error" data-error-for="phone"></div></div>
</fieldset>

<div class="summary"><table><tbody id="aih-summary-rows"><tr><td>Preise werden geladen …</td><td></td></tr></tbody></table></div>

<p><label class="terms"><input type="checkbox" name="terms" value="1" required> <span>Ich akzeptiere die <a id="aih-terms-link" href="/agb/" target="_blank" rel="noopener">AGB</a> (Version <span id="aih-terms-version">…</span>) und die Bearbeitung meiner Angaben gemäss <a href="/datenschutz/">Datenschutzerklärung</a>.</span></label></p>
<div class="error" data-error-for="terms"></div>

<div class="submit" style="text-align:left;margin-top:16px"><button class="btn" type="submit">Kostenpflichtig bestellen</button></div>
<p class="hint" style="margin-top:16px">Es entsteht ein Jahresabo, das sich automatisch verlängert und bis zum Ende der laufenden Periode kündbar ist. Die Rechnung für das Folgejahr kommt mindestens einen Monat vor dem Verlängerungsdatum.</p>
<noscript><p class="hint">Für das Bestellformular wird JavaScript benötigt. Alternativ bestellen Sie über das <a href="/kontakt/">Kontaktformular</a>.</p></noscript>
</form>
</div></section>
<script src="/assets/signup.js"></script>
"""

THANKS_BODY = """<section class="hero center"><div class="wrap"><div class="inner">
<div id="aih-step-confirm">
<h1 style="font-weight:200">Bitte bestätigen Sie Ihre E-Mail-Adresse.</h1>
<p class="lead">Ihre Bestellung ist eingegangen<span class="aih-order-no"></span>. Wir haben Ihnen eine E-Mail mit einem Bestätigungslink geschickt. Bitte klicken Sie auf den Link; erst danach stellen wir die Rechnung aus.</p>
<p style="font-size:.9rem;color:var(--muted)">Keine E-Mail erhalten? Bitte den Spam-Ordner prüfen. Der Link ist 48 Stunden gültig; danach verfällt die Bestellung ohne Kosten.</p>
</div>
<div id="aih-step-confirmed" hidden>
<h1 style="font-weight:200">Vielen Dank, Ihre Bestellung ist bestätigt.</h1>
<p class="lead">Die Rechnung<span class="aih-order-no"></span> kommt in den nächsten Minuten per E-Mail; Sie können per QR-Rechnung oder Kreditkarte bezahlen.</p>
<p class="lead">Sobald die Zahlung eingegangen ist, wird Ihr Hosting automatisch freigeschaltet. Sie erhalten dann eine E-Mail mit dem Link zum Setzen Ihres Passworts, den Angaben zur Domain und der Anleitung für den KI-Zugang.</p>
<p style="font-size:.9rem;color:var(--muted)">Keine Rechnung erhalten? Bitte auch den Spam-Ordner prüfen oder uns über das <a href="/kontakt/">Kontaktformular</a> schreiben.</p>
</div>
<div class="actions btn-row" style="justify-content:center"><a class="btn" href="/">Zur Startseite</a><a class="btn ghost" href="/ki-hosting/">Zum AI Hosting</a></div>
</div></div></section>
<script>(function(){var q=location.search;var m=/[?&]order=([a-f0-9]{16})/.exec(q);if(m){[].forEach.call(document.querySelectorAll(".aih-order-no"),function(e){e.textContent=" (Bestell-Nr. "+m[1]+")"})}
if(/[?&]step=confirmed/.test(q)){document.getElementById("aih-step-confirm").hidden=true;document.getElementById("aih-step-confirmed").hidden=false}})();</script>
"""


def domains_body(price_list: dict) -> str:
    rows = []
    for t in price_list["tlds"]:
        price = f"Fr. {t['price_per_year']:.2f}" if t.get("price_per_year") is not None else "auf Anfrage"
        rows.append(f'<tr><th scope="row">.{t["tld"]}</th><td>{price}</td></tr>')
    return (
        """<section class="hero" style="padding:110px 0 40px"><div class="wrap"><div class="hero-art short" aria-hidden="true"><span class="glow-fx" data-op="0.69" style="background-image:url(/assets/img/glow.svg);background-position:100% 50%;opacity:.69"></span><span class="pin" style="background-image:url(/assets/img/pin.png)"></span><div class="lottie" data-lottie="/assets/lottie/contact-circ.json"></div></div><div class="inner" style="max-width:760px">
<h1 style="font-weight:200">Domains</h1>
<p class="lead">Der Wegweiser im World Wide Web…</p></div></div></section>
<section style="padding-top:24px"><div class="wrap">
<p style="max-width:720px">Ergänzend zu den anderen Dienstleistungen werden auch Domains angeboten, <a href="/kontakt/">kontaktieren</a> Sie uns für ungenannte Domainendungen und deren Preise. Alle hier gelisteten Endungen ausser .swiss lassen sich zusammen mit <a href="/ki-hosting/">AI Hosting</a> <a href="/ki-hosting/bestellen/">online bestellen</a>.</p>
<table class="prices-table" id="domains-table"><caption class="sr">Domainpreise</caption><thead><tr><th scope="col">Endung</th><th scope="col">Preis pro Jahr</th></tr></thead><tbody>
"""
        + "\n".join(rows)
        + f"""
</tbody></table>
<p class="note2" id="domains-updated">Preise inkl. MwSt, vorbehaltlich Änderungen. Letzte Anpassung: {price_list.get('updated', '')}</p>
</div></section>
<script src="/assets/domains.js"></script>
"""
    )


def main(out: str) -> None:
    import json

    with open(os.path.join(HERE, "..", "assets", "domains.json"), encoding="utf-8") as fh:
        price_list = json.load(fh)
    pages = {
        "ki-hosting/bestellen/index.html": page(
            title="AI Hosting bestellen", description="AI Hosting bestellen: 5 GB Webhosting mit KI-Zugang für CHF 60.– pro Jahr, eigene oder neue Domain, Freischaltung automatisch nach Zahlung.",
            path="/ki-hosting/bestellen/", body=ORDER_BODY.replace("__SIGNUP_BASE__", SIGNUP_BASE), robots="noindex, follow", head_extra=FORM_CSS, current=True,
        ),
        "ki-hosting/danke/index.html": page(
            title="Bestellung eingegangen", description="Ihre Bestellung für AI Hosting ist eingegangen: E-Mail bestätigen, dann kommt die Rechnung.", path="/ki-hosting/danke/", body=THANKS_BODY, robots="noindex, nofollow", current=True,
        ),
        "domains/index.html": page(
            title="Domains", description="Domainpreise der tabside GmbH: .ch, .com, .swiss und weitere Endungen.", path="/domains/", body=domains_body(price_list),
            head_extra='<script defer src="/assets/lottie.min.js"></script>\n<script defer src="/assets/hero.js"></script>\n',
        ),
    }
    for rel, html in pages.items():
        target = os.path.join(out, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(html)
        print("wrote", target)
    for name in ("signup.js", "domains.js", "domains.json"):
        src = os.path.join(HERE, "..", "assets", name)
        with open(src, encoding="utf-8") as fh:
            content = fh.read().replace("https://mcp.example.com/plesk", SIGNUP_BASE)
        os.makedirs(os.path.join(out, "assets"), exist_ok=True)
        with open(os.path.join(out, "assets", name), "w", encoding="utf-8") as fh:
            fh.write(content)
        print("wrote", os.path.join(out, "assets", name))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "dist"))
