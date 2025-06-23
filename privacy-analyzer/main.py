from fasthtml.common import *
import re
import datetime
import json


LINKS = {
    "uBlock Origin (Firefox)": "https://addons.mozilla.org/de/firefox/addon/ublock-origin/",
    "uBlock Origin (Chrome)": "https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm",
    "Privacy Badger (Firefox)": "https://addons.mozilla.org/de/firefox/addon/privacy-badger17/",
    "Privacy Badger (Chrome)": "https://chrome.google.com/webstore/detail/privacy-badger/pkehgijcmpdhfbdbbnkijodmdjhbjlgp",
    "CanvasBlocker (Firefox)": "https://addons.mozilla.org/de/firefox/addon/canvasblocker/",
    "Cookie AutoDelete (Firefox)": "https://addons.mozilla.org/de/firefox/addon/cookie-autodelete/",
    "Cookie AutoDelete (Chrome)": "https://chrome.google.com/webstore/detail/cookie-autodelete/fhcgjolkccmbidfldomjliifgaodjagh",
    "User-Agent Switcher (Firefox)": "https://addons.mozilla.org/de/firefox/addon/user-agent-switcher-revived/",
    "User-Agent Switcher (Chrome)": "https://chrome.google.com/webstore/detail/user-agent-switcher-for-c/ljdobmomdgdljniojadhoplhkpialdid",
    "Brave Browser": "https://brave.com/de/download/",
    "Firefox Browser": "https://www.mozilla.org/de/firefox/new/",
    "EFF Cover Your Tracks": "https://coveryourtracks.eff.org/",
    "AmIUnique": "https://amiunique.org/",
    "Ghostery (Firefox)": "https://addons.mozilla.org/de/firefox/addon/ghostery/",
    "Ghostery (Chrome)": "https://chrome.google.com/webstore/detail/ghostery-gamer/mlomiejdfkolichcflejclcbmpeaniij",
    "FMHY Beginners Guide": "https://fmhy.net/beginners-guide",
    "WhatIsMyBrowser": "https://www.whatismybrowser.com/guides/the-latest-user-agent/",
}


def AddonLink(txt, url, recommended=False):
    cls = "button recommended" if recommended else "button"
    return A(txt, href=url, target="_blank", rel="noopener", cls=cls)


def PrivacyIssue(text, severity="warning"):
    icon = (
        "⚠️"
        if severity == "warning"
        else "❌" if severity == "high" else "ℹ️" if severity == "info" else "✅"
    )
    cls = f"privacy-issue {severity}"
    return Div(Span(icon), " ", text, cls=cls)


def CheckRow(label, value, issues=None, row_id=None):
    cells = [
        Td(label, cls="label"),
        Td(value, id=f"{row_id}-value" if row_id else None),
    ]
    if issues:
        cells.append(
            Td(*issues, cls="issues", id=f"{row_id}-issues" if row_id else None)
        )
    return Tr(*cells, id=row_id)


def is_common_user_agent(ua):
    """Check if user agent appears to be commonly used"""
    if not ua:
        return False

    # Check for very specific/uncommon patterns
    uncommon_patterns = [
        r"HeadlessChrome",
        r"PhantomJS",
        r"Selenium",
        r"Bot",
        r"Spider",
        r"Crawler",
        r"automated",
        r"test",
    ]

    for pattern in uncommon_patterns:
        if re.search(pattern, ua, re.IGNORECASE):
            return False

    # Very long or very short user agents are uncommon
    if len(ua) < 50 or len(ua) > 200:
        return False

    return True


def analyze_user_agent(ua):
    """Analyze user agent for privacy concerns"""
    issues = []

    if not ua:
        issues.append(
            PrivacyIssue("Kein User-Agent gefunden - sehr ungewöhnlich", "high")
        )
        return issues

    # Check for common browsers and versions
    if "Chrome" in ua and "Firefox" not in ua:
        issues.append(PrivacyIssue("Chrome sammelt viele Nutzerdaten", "warning"))

    if "Edge" in ua:
        issues.append(
            PrivacyIssue("Microsoft Edge teilt Daten mit Microsoft", "warning")
        )

    # Check if it's a common user agent
    if not is_common_user_agent(ua):
        issues.append(
            PrivacyIssue(
                "Ungewöhnlicher User-Agent erhöht Fingerprinting-Risiko", "high"
            )
        )

    # Check for detailed version info (fingerprinting risk)
    version_matches = re.findall(r"/[\d.]+", ua)
    if len(version_matches) > 4:
        issues.append(
            PrivacyIssue("Sehr detaillierte Versionsinformationen", "warning")
        )

    return issues


def analyze_language(lang):
    """Analyze language headers for privacy concerns"""
    issues = []

    if not lang:
        return [PrivacyIssue("Keine Sprachpräferenz - gut für Privatsphäre", "good")]

    # Count languages - more languages = more fingerprinting potential
    languages = lang.split(",")
    if len(languages) > 3:
        issues.append(
            PrivacyIssue("Viele Sprachen erhöhen Fingerprinting-Risiko", "warning")
        )

    # Check for very specific locale info
    if any(";q=" in l for l in languages):
        issues.append(PrivacyIssue("Detaillierte Sprachgewichtung sichtbar", "warning"))

    return issues


def analyze_ip(ip):
    """Analyze IP for privacy concerns"""
    issues = []

    if not ip or ip == "127.0.0.1" or ip.startswith("192.168."):
        issues.append(PrivacyIssue("Lokale IP-Adresse", "good"))
    else:
        issues.append(
            PrivacyIssue("Öffentliche IP sichtbar - nutzen Sie VPN/Proxy", "warning")
        )
        issues.append(
            PrivacyIssue("Wenn Sie bereits VPN/Proxy nutzen: ✅ Gut!", "good")
        )

    return issues


def get_recommendations(ua, ip, lang, has_cookies):
    """Get personalized recommendations based on analysis"""
    recommendations = []

    # Basic privacy recommendations
    recommendations.append(
        (
            "uBlock Origin",
            ["uBlock Origin (Firefox)", "uBlock Origin (Chrome)"],
            True,
        )
    )

    recommendations.append(
        (
            "Privacy Badger",
            ["Privacy Badger (Firefox)", "Privacy Badger (Chrome)"],
            True,
        )
    )

    # Chrome-specific recommendations
    if "Chrome" in ua and "Firefox" not in ua:
        recommendations.append(
            (
                "Ghostery (Alternative)",
                ["Ghostery (Firefox)", "Ghostery (Chrome)"],
                True,
            )
        )

    # Cookie recommendations
    if has_cookies:
        recommendations.append(
            (
                "Cookie AutoDelete",
                ["Cookie AutoDelete (Firefox)", "Cookie AutoDelete (Chrome)"],
                True,
            )
        )

    # User agent recommendations
    if not is_common_user_agent(ua):
        recommendations.append(
            (
                "User-Agent Switcher (für gängige UA)",
                ["User-Agent Switcher (Firefox)", "User-Agent Switcher (Chrome)"],
                True,
            )
        )
    else:
        recommendations.append(
            (
                "User-Agent Switcher",
                ["User-Agent Switcher (Firefox)", "User-Agent Switcher (Chrome)"],
                False,
            )
        )

    # Advanced recommendations
    recommendations.append(("CanvasBlocker", ["CanvasBlocker (Firefox)"], False))

    return recommendations


def get_useragent(req):
    return req.headers.get("user-agent", "")


def get_ip(req):
    return req.client.host


def get_lang(req):
    return req.headers.get("accept-language", "")


def get_tz():
    return datetime.datetime.now(datetime.timezone.utc).astimezone().tzname()


# Enhanced CSS
css = """
.recommended { 
    background: #2d5a27 !important; 
    color: white !important;
    font-weight: bold;
}
.privacy-issue {
    margin: 2px 0;
    padding: 3px 6px;
    border-radius: 3px;
    font-size: 0.9em;
}
.privacy-issue.warning {
    background: #fff3cd;
    color: #856404;
    border: 1px solid #ffeaa7;
}
.privacy-issue.high {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}
.privacy-issue.info {
    background: #d1ecf1;
    color: #0c5460;
    border: 1px solid #bee5eb;
}
.privacy-issue.good {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}
.issues { width: 40%; }
.label { font-weight: bold; width: 25%; }
table { width: 100%; border-collapse: collapse; margin: 1em 0; }
td, th { padding: 8px; border: 1px solid #ddd; text-align: left; }
.striped tr:nth-child(even) { background-color: #f9f9f9; }
.muted_sm { color: #666; font-size: 0.9em; margin-top: 2em; }
.recommendation-section { margin: 1.5em 0; }
.critical { background: #ffebee; padding: 1em; border-left: 4px solid #f44336; margin: 1em 0; }
.loading { color: #666; font-style: italic; }
"""

# Main Route
app, rt = fast_app(hdrs=[Style(css)])


@rt("/")
def index(req):
    # Daten auslesen
    ua = get_useragent(req)
    ip = get_ip(req)
    lang = get_lang(req)
    tz = get_tz()
    has_cookies = bool(req.cookies)

    # Analyse durchführen
    ua_issues = analyze_user_agent(ua)
    ip_issues = analyze_ip(ip)
    lang_issues = analyze_language(lang)

    # Info-Tabelle mit Analyse
    table = Table(
        Thead(Tr(Th("Merkmal"), Th("Ihr Wert"), Th("Datenschutz-Bewertung"))),
        Tbody(
            CheckRow("IP-Adresse", Code(ip), ip_issues),
            CheckRow("Sprache", Code(lang), lang_issues),
            CheckRow(
                "Zeitzone",
                Code(tz),
                [PrivacyIssue("Zeitzone kann Standort preisgeben", "warning")],
            ),
            CheckRow(
                "Cookies aktiviert",
                Code("Ja" if has_cookies else "Nein"),
                (
                    [PrivacyIssue("Cookies ermöglichen Tracking", "warning")]
                    if has_cookies
                    else []
                ),
            ),
            CheckRow(
                "Browser / User-Agent",
                Code(ua[:100] + "..." if len(ua) > 100 else ua),
                ua_issues,
            ),
        ),
        cls="striped",
    )

    # Personalisierte Empfehlungen
    recommendations = get_recommendations(ua, ip, lang, has_cookies)

    addon_list = []
    for name, link_keys, is_recommended in recommendations:
        links = []
        for key in link_keys:
            if key in LINKS:
                browser_type = "Firefox" if "Firefox" in key else "Chrome"
                links.append(
                    AddonLink(f"{name} ({browser_type})", LINKS[key], is_recommended)
                )

        if links:
            addon_list.append(
                Li(
                    *[
                        item
                        for sublist in [[link, Nbsp()] for link in links[:-1]]
                        + [[links[-1]]]
                        for item in sublist
                    ]
                )
            )

    # Browser-Empfehlungen (ohne Tor)
    browser_recommendations = Ul(
        Li(
            "Datenschutz-fokussiert: ",
            AddonLink("Firefox", LINKS["Firefox Browser"], True),
            " (mit Addons konfiguriert)",
        ),
        Li("Out-of-the-box Schutz: ", AddonLink("Brave", LINKS["Brave Browser"], True)),
        Li("Für Experten: Firefox mit strikten Einstellungen"),
    )

    # Test-Links
    tests = Ul(
        Li(AddonLink("EFF Cover Your Tracks", LINKS["EFF Cover Your Tracks"])),
        Li(AddonLink("AmIUnique", LINKS["AmIUnique"])),
        Li(AddonLink("Aktuelle User-Agents", LINKS["WhatIsMyBrowser"])),
    )

    # Alternative Plattformen
    alternatives = Ul(
        Li(AddonLink("FMHY - Alternatives to Big Tech", LINKS["FMHY Beginners Guide"])),
        Li("Open Source Alternativen zu proprietären Services"),
        Li("Datenschutzfreundliche Suchmaschinen (DuckDuckGo, Startpage)"),
    )

    # Kritische Warnungen
    critical_issues = []
    if (
        not (ip == "127.0.0.1" or ip.startswith("192.168."))
        and "relay" not in ip.lower()
    ):
        critical_issues.append("Überprüfen Sie, ob Ihr VPN/Proxy korrekt funktioniert!")
    if "Chrome" in ua and "Firefox" not in ua:
        critical_issues.append(
            "Chrome sammelt extensive Nutzerdaten - wechseln Sie zu Firefox oder Brave!"
        )

    critical_section = ""
    if critical_issues:
        critical_section = Div(
            H3("🚨 Kritische Datenschutzprobleme"),
            *[P(issue) for issue in critical_issues],
            cls="critical",
        )

    return Titled(
        "Privacy Check & Tools",
        critical_section,
        H2("🔍 Ihre Browserdaten & Analyse"),
        table,
        H2("🛡️ Personalisierte Addon-Empfehlungen"),
        P("Grün markierte Addons sind für Ihre Konfiguration besonders empfohlen:"),
        Ul(*addon_list),
        H2("🌐 Browser-Empfehlung"),
        browser_recommendations,
        H2("🧪 Testen Sie Ihre Privatsphäre"),
        tests,
        H2("🔄 Alternativen zu Big Tech"),
        alternatives,
        Div(
            "💡 Tipp: Kombinieren Sie mehrere Schutzmaßnahmen für optimale Privatsphäre. Ein VPN/Proxy allein reicht nicht aus.",
            cls="muted_sm",
        ),
        style="max-width:900px;margin:auto;padding:20px;",
    )


serve()
