from fasthtml.common import *
import re
import datetime

# Addon-Links
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
    "Tor Browser": "https://www.torproject.org/download/",
    "EFF Cover Your Tracks": "https://coveryourtracks.eff.org/",
    "AmIUnique": "https://amiunique.org/",
    "Ghostery (Firefox)": "https://addons.mozilla.org/de/firefox/addon/ghostery/",
    "Ghostery (Chrome)": "https://chrome.google.com/webstore/detail/ghostery-gamer/mlomiejdfkolichcflejclcbmpeaniij",
}

def AddonLink(txt, url, recommended=False): 
    cls = "button recommended" if recommended else "button"
    return A(txt, href=url, target="_blank", rel="noopener", cls=cls)

def PrivacyIssue(text, severity="warning"):
    icon = "⚠️" if severity == "warning" else "❌" if severity == "high" else "ℹ️"
    cls = f"privacy-issue {severity}"
    return Div(Span(icon), " ", text, cls=cls)

def CheckRow(label, value, issues=None):
    cells = [
        Td(label, cls="label"),
        Td(value)
    ]
    if issues:
        cells.append(Td(*issues, cls="issues"))
    return Tr(*cells)

def analyze_user_agent(ua):
    """Analyze user agent for privacy concerns"""
    issues = []
    
    if not ua:
        issues.append(PrivacyIssue("Kein User-Agent gefunden", "info"))
        return issues
    
    # Check for common browsers and versions
    if "Chrome" in ua and "Firefox" not in ua:
        issues.append(PrivacyIssue("Chrome sammelt viele Nutzerdaten", "warning"))
    
    if "Edge" in ua:
        issues.append(PrivacyIssue("Microsoft Edge teilt Daten mit Microsoft", "warning"))
    
    # Check for detailed version info (fingerprinting risk)
    version_matches = re.findall(r'/[\d.]+', ua)
    if len(version_matches) > 3:
        issues.append(PrivacyIssue("Sehr detaillierte Versionsinformationen erhöhen Fingerprinting-Risiko", "warning"))
    
    # Check for plugins/extensions mentioned in UA
    if "Plugin" in ua or "Extension" in ua:
        issues.append(PrivacyIssue("Plugin-Informationen im User-Agent sichtbar", "high"))
    
    return issues

def analyze_language(lang):
    """Analyze language headers for privacy concerns"""
    issues = []
    
    if not lang:
        return [PrivacyIssue("Keine Sprachpräferenz übertragen", "info")]
    
    # Count languages - more languages = more fingerprinting potential
    languages = lang.split(',')
    if len(languages) > 3:
        issues.append(PrivacyIssue("Viele Sprachen erhöhen Fingerprinting-Risiko", "warning"))
    
    # Check for very specific locale info
    if any(';q=' in l for l in languages):
        issues.append(PrivacyIssue("Detaillierte Sprachgewichtung sichtbar", "warning"))
    
    return issues

def analyze_ip(ip):
    """Analyze IP for privacy concerns"""
    issues = []
    
    if not ip or ip == "127.0.0.1" or ip.startswith("192.168."):
        issues.append(PrivacyIssue("Lokale IP-Adresse", "info"))
    else:
        issues.append(PrivacyIssue("Öffentliche IP-Adresse sichtbar - nutzen Sie ein VPN", "high"))
    
    return issues

def get_recommendations(ua, ip, lang, has_cookies):
    """Get personalized recommendations based on analysis"""
    recommendations = []
    
    # Basic recommendations for everyone
    recommendations.extend([
        ("uBlock Origin", ["uBlock Origin (Firefox)", "uBlock Origin (Chrome)"], True),
        ("Privacy Badger", ["Privacy Badger (Firefox)", "Privacy Badger (Chrome)"], True),
    ])
    
    # Chrome-specific recommendations
    if "Chrome" in ua and "Firefox" not in ua:
        recommendations.append(("Ghostery (Alternative)", ["Ghostery (Firefox)", "Ghostery (Chrome)"], True))
    
    # Cookie recommendations
    if has_cookies:
        recommendations.append(("Cookie AutoDelete", ["Cookie AutoDelete (Firefox)", "Cookie AutoDelete (Chrome)"], True))
    
    # Advanced recommendations
    recommendations.extend([
        ("CanvasBlocker", ["CanvasBlocker (Firefox)"], False),
        ("User-Agent Switcher", ["User-Agent Switcher (Firefox)", "User-Agent Switcher (Chrome)"], False),
    ])
    
    return recommendations

def get_useragent(req): return req.headers.get("user-agent", "")
def get_ip(req): return req.client.host
def get_lang(req): return req.headers.get("accept-language", "")
def get_tz(): return datetime.datetime.now(datetime.timezone.utc).astimezone().tzname()
def get_dnt(req): return req.headers.get("dnt", "")

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
.issues { width: 40%; }
.label { font-weight: bold; width: 25%; }
table { width: 100%; border-collapse: collapse; margin: 1em 0; }
td, th { padding: 8px; border: 1px solid #ddd; text-align: left; }
.striped tr:nth-child(even) { background-color: #f9f9f9; }
.muted_sm { color: #666; font-size: 0.9em; margin-top: 2em; }
.recommendation-section { margin: 1.5em 0; }
.critical { background: #ffebee; padding: 1em; border-left: 4px solid #f44336; margin: 1em 0; }
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
    dnt = get_dnt(req)
    has_cookies = bool(req.cookies)
    
    # Analyse durchführen
    ua_issues = analyze_user_agent(ua)
    ip_issues = analyze_ip(ip)
    lang_issues = analyze_language(lang)
    
    # Info-Tabelle mit Analyse
    table = Table(
        Thead(Tr(Th("Merkmal"), Th("Ihr Wert"), Th("Datenschutz-Bewertung"))),
        Tbody(
            CheckRow("Browser / User-Agent", Code(ua[:100] + "..." if len(ua) > 100 else ua), ua_issues),
            CheckRow("IP-Adresse", Code(ip), ip_issues),
            CheckRow("Sprache", Code(lang), lang_issues),
            CheckRow("Zeitzone", Code(tz), [PrivacyIssue("Zeitzone kann Standort preisgeben", "warning")]),
            CheckRow("Do Not Track", Code(dnt if dnt else "Nicht gesetzt"), 
                    [PrivacyIssue("DNT aktivieren für besseren Schutz", "info")] if not dnt else []),
            CheckRow("Cookies aktiviert", Code("Ja" if has_cookies else "Nein"), 
                    [PrivacyIssue("Cookies ermöglichen Tracking", "warning")] if has_cookies else []),
        ),
        cls="striped"
    )
    
    # Personalisierte Empfehlungen
    recommendations = get_recommendations(ua, ip, lang, has_cookies)
    
    addon_list = []
    for name, link_keys, is_recommended in recommendations:
        links = []
        for key in link_keys:
            if key in LINKS:
                browser_type = "Firefox" if "Firefox" in key else "Chrome"
                links.append(AddonLink(f"{name} ({browser_type})", LINKS[key], is_recommended))
        
        if links:
            addon_list.append(Li(*[item for sublist in [[link, Nbsp()] for link in links[:-1]] + [[links[-1]]] for item in sublist]))
    
    # Browser-Empfehlungen
    browser_recommendations = Ul(
        Li("Höchste Privatsphäre: ", AddonLink("Tor Browser", LINKS["Tor Browser"], True)),
        Li("Guter Kompromiss: ", AddonLink("Firefox", LINKS["Firefox Browser"], True), Nbsp(), AddonLink("Brave", LINKS["Brave Browser"], True))
    )
    
    # Test-Links
    tests = Ul(
        Li(AddonLink("EFF Cover Your Tracks", LINKS["EFF Cover Your Tracks"])),
        Li(AddonLink("AmIUnique", LINKS["AmIUnique"]))
    )
    
    # Kritische Warnungen
    critical_issues = []
    if ip and not (ip == "127.0.0.1" or ip.startswith("192.168.")):
        critical_issues.append("Ihre echte IP-Adresse ist sichtbar - verwenden Sie ein VPN!")
    if "Chrome" in ua and "Firefox" not in ua:
        critical_issues.append("Chrome sammelt extensive Nutzerdaten - wechseln Sie zu Firefox oder Brave!")
    
    critical_section = ""
    if critical_issues:
        critical_section = Div(
            H3("🚨 Kritische Datenschutzprobleme"),
            *[P(issue) for issue in critical_issues],
            cls="critical"
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
        Div(
            "💡 Tipp: Für vollständigen Schutz nutzen Sie zusätzlich VPN, Privatmodus und regelmäßiges Löschen von Browser-Daten.",
            cls="muted_sm"
        ),
        style="max-width:900px;margin:auto;padding:20px;"
    )

serve()