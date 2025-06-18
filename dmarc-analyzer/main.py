from fasthtml.common import *
import xml.etree.ElementTree as ET
from io import BytesIO
import datetime

app, rt = fast_app()

def parse_dmarc_xml(uploaded_file):
    """Parse DMARC XML file and return structured data"""
    try:
        # Read file content
        content = uploaded_file.file.read()
        tree = ET.parse(BytesIO(content))
        root = tree.getroot()
    except Exception as e:
        return None, [f"Fehler beim Parsen der XML: {e}"], [], [], [], {}

    # Extract metadata
    meta = {}
    meta['org'] = root.findtext('./report_metadata/org_name', default='Unbekannt')
    meta['domain'] = root.findtext('./policy_published/domain', default='Unbekannt')
    meta['email'] = root.findtext('./report_metadata/email', default='')
    
    # Parse date range
    begin = root.findtext('./report_metadata/date_range/begin')
    end = root.findtext('./report_metadata/date_range/end')
    if begin and end:
        try:
            meta['begin'] = datetime.datetime.fromtimestamp(int(begin))
            meta['end'] = datetime.datetime.fromtimestamp(int(end))
        except (ValueError, TypeError):
            meta['begin'] = meta['end'] = None
    else:
        meta['begin'] = meta['end'] = None

    # Extract policy
    policy = root.find('./policy_published')
    if policy is None:
        return None, ["<policy_published> Element fehlt in der XML"], [], [], [], meta
    
    meta['dmarc_policy'] = policy.findtext('p', default='none')
    meta['sp_policy'] = policy.findtext('sp', default='none')
    meta['pct'] = policy.findtext('pct', default='100')
    meta['adkim'] = policy.findtext('adkim', default='r')  # DKIM alignment
    meta['aspf'] = policy.findtext('aspf', default='r')   # SPF alignment

    # Parse records
    records = []
    good_records = []
    warning_records = []
    error_records = []

    for rec in root.findall('./record'):
        ip = rec.findtext('./row/source_ip', default='Unbekannt')
        count = rec.findtext('./row/count', default='1')
        disp = rec.findtext('./row/policy_evaluated/disposition', default='none')
        spf = rec.findtext('./row/policy_evaluated/spf', default='fail')
        dkim = rec.findtext('./row/policy_evaluated/dkim', default='fail')
        
        # Additional details
        header_from = rec.findtext('./identifiers/header_from', default='')
        
        try:
            count = int(count)
        except (ValueError, TypeError):
            count = 1

        entry = {
            'ip': ip,
            'count': count,
            'disposition': disp,
            'spf': spf,
            'dkim': dkim,
            'header_from': header_from
        }

        # Categorize records
        if disp == "none" and spf == "pass" and dkim == "pass":
            good_records.append(entry)
        elif disp == "none" and (spf == "pass" or dkim == "pass"):
            warning_records.append(entry)
        else:
            error_records.append(entry)

        records.append(entry)

    return records, [], good_records, warning_records, error_records, meta

def create_summary_boxes(good_records, warning_records, error_records, meta):
    """Create summary boxes with color-coded results"""
    boxes = []
    
    total_messages = sum(r['count'] for r in good_records + warning_records + error_records)
    
    if good_records:
        total_good = sum(r['count'] for r in good_records)
        boxes.append(
            Div(
                f"✅ {len(good_records)} IP-Adressen ({total_good} Nachrichten) - Vollständig authentifiziert",
                style="padding: 10px; margin: 5px 0; background: #d4edda; color: #155724; border: 1px solid #c3e6cb; border-radius: 4px; font-weight: bold;"
            )
        )
    
    if warning_records:
        total_warning = sum(r['count'] for r in warning_records)
        boxes.append(
            Div(
                f"⚠️ {len(warning_records)} IP-Adressen ({total_warning} Nachrichten) - Teilweise authentifiziert",
                style="padding: 10px; margin: 5px 0; background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; border-radius: 4px; font-weight: bold;"
            )
        )
    
    if error_records:
        total_error = sum(r['count'] for r in error_records)
        boxes.append(
            Div(
                f"❌ {len(error_records)} IP-Adressen ({total_error} Nachrichten) - Authentifizierung fehlgeschlagen",
                style="padding: 10px; margin: 5px 0; background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; border-radius: 4px; font-weight: bold;"
            )
        )
    
    if not (good_records or warning_records or error_records):
        boxes.append(
            Div(
                "ℹ️ Keine E-Mail-Sendeversuche in diesem Bericht gefunden",
                style="padding: 10px; margin: 5px 0; background: #e2e3e5; color: #383d41; border: 1px solid #d6d8db; border-radius: 4px;"
            )
        )
    
    # Policy warning
    if meta.get("dmarc_policy", "none") == "none":
        boxes.append(
            Div(
                "⚠️ DMARC-Policy ist auf 'none' gesetzt - E-Mails werden nicht abgelehnt, auch bei fehlgeschlagener Authentifizierung!",
                style="padding: 10px; margin: 5px 0; background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; border-radius: 4px; font-weight: bold;"
            )
        )
    
    return boxes

def create_records_table(records):
    """Create a table of all records with color coding"""
    if not records:
        return P("Keine Einträge gefunden.", style="color: #6c757d; font-style: italic;")
    
    # Table header
    header = Tr(
        Th("IP-Adresse", style="padding: 8px; text-align: left;"),
        Th("SPF", style="padding: 8px; text-align: center;"),
        Th("DKIM", style="padding: 8px; text-align: center;"),
        Th("Disposition", style="padding: 8px; text-align: center;"),
        Th("Anzahl", style="padding: 8px; text-align: right;"),
        Th("Header From", style="padding: 8px; text-align: left;"),
        style="background-color: #f8f9fa;"
    )
    
    # Table rows
    rows = []
    for r in records:
        # Determine row color based on authentication status
        if r["disposition"] == "none" and r["spf"] == "pass" and r["dkim"] == "pass":
            row_style = "background-color: #d4edda; color: #155724;"
        elif r["disposition"] == "none" and (r["spf"] == "pass" or r["dkim"] == "pass"):
            row_style = "background-color: #fff3cd; color: #856404;"
        else:
            row_style = "background-color: #f8d7da; color: #721c24;"
        
        rows.append(
            Tr(
                Td(r["ip"], style="padding: 8px; font-family: monospace;"),
                Td(r["spf"], style="padding: 8px; text-align: center; font-weight: bold;"),
                Td(r["dkim"], style="padding: 8px; text-align: center; font-weight: bold;"),
                Td(r["disposition"], style="padding: 8px; text-align: center;"),
                Td(str(r["count"]), style="padding: 8px; text-align: right; font-weight: bold;"),
                Td(r["header_from"] or "-", style="padding: 8px; font-family: monospace;"),
                style=row_style
            )
        )
    
    return Table(
        Thead(header),
        Tbody(*rows),
        style="width: 100%; border-collapse: collapse; border: 1px solid #dee2e6; margin: 10px 0;"
    )

def create_policy_info(meta):
    """Create policy information section"""
    policy_items = [
        f"Domain: {meta.get('domain', 'Unbekannt')}",
        f"DMARC-Policy: {meta.get('dmarc_policy', 'none')}",
        f"Subdomain-Policy: {meta.get('sp_policy', 'none')}",
        f"Prozentsatz: {meta.get('pct', '100')}%",
        f"DKIM-Alignment: {meta.get('adkim', 'r')} ({'relaxed' if meta.get('adkim', 'r') == 'r' else 'strict'})",
        f"SPF-Alignment: {meta.get('aspf', 'r')} ({'relaxed' if meta.get('aspf', 'r') == 'r' else 'strict'})"
    ]
    
    return Ul(*[Li(item, style="margin: 5px 0;") for item in policy_items])

@rt("/", methods=["GET"])
def index():
    """Main page with file upload form"""
    return Titled(
        "DMARC XML Report Analyzer",
        Div(
            H1("DMARC XML Report Analyzer", style="color: #343a40; margin-bottom: 20px;"),
            P("Laden Sie Ihren DMARC XML Report hoch, um eine detaillierte Analyse zu erhalten.", 
              style="color: #6c757d; margin-bottom: 20px;"),
            Form(
                Div(
                    Label("DMARC XML-Datei auswählen:", 
                          style="display: block; margin-bottom: 8px; font-weight: bold;"),
                    Input(type="file", name="dmarcxml", accept=".xml", required=True,
                          style="margin-bottom: 15px; padding: 8px; border: 1px solid #ced4da; border-radius: 4px; width: 100%;"),
                    Button("Bericht analysieren", type="submit",
                           style="background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;"),
                    style="max-width: 500px;"
                ),
                method="post", 
                enctype="multipart/form-data", 
                hx_post="/analyze", 
                hx_target="#result", 
                hx_swap="innerHTML",
                hx_indicator="#loading"
            ),
            Div(
                "🔄 Analysiere...", 
                id="loading", 
                style="display: none; margin: 20px 0; color: #007bff; font-weight: bold;"
            ),
            Div(id="result", style="margin-top: 30px;"),
            style="max-width: 1200px; margin: 0 auto; padding: 20px;"
        )
    )

@rt("/analyze", methods=["POST"])
async def analyze_dmarc(dmarcxml: UploadFile):
    """Analyze uploaded DMARC XML file"""
    if not dmarcxml.filename:
        return Div(
            "❌ Keine Datei ausgewählt",
            id="result",
            style="color: #dc3545; font-weight: bold; padding: 20px; background: #f8d7da; border-radius: 4px;"
        )
    
    # Parse the XML
    records, parse_errors, good_records, warning_records, error_records, meta = parse_dmarc_xml(dmarcxml)
    
    if parse_errors:
        return Div(
            H3("❌ Fehler beim Parsen der XML-Datei", style="color: #dc3545;"),
            Ul(*[Li(error, style="color: #dc3545;") for error in parse_errors]),
            id="result",
            style="padding: 20px; background: #f8d7da; border-radius: 4px; margin: 20px 0;"
        )
    
    content = []
    
    # Header with metadata
    content.append(
        Div(
            H2(f"📊 DMARC Report für {meta.get('domain', 'Unbekannt')}", 
               style="color: #343a40; margin-bottom: 10px;"),
            P(f"Organisation: {meta.get('org', 'Unbekannt')}", 
              style="margin: 5px 0; color: #6c757d;"),
            P(f"Berichtszeitraum: {meta['begin'].strftime('%d.%m.%Y %H:%M') if meta.get('begin') else 'Unbekannt'} - {meta['end'].strftime('%d.%m.%Y %H:%M') if meta.get('end') else 'Unbekannt'}", 
              style="margin: 5px 0; color: #6c757d;") if meta.get('begin') and meta.get('end') else None,
            style="margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 4px;"
        )
    )
    
    # Summary boxes
    content.append(H3("📈 Zusammenfassung", style="color: #343a40; margin: 20px 0 10px 0;"))
    content.extend(create_summary_boxes(good_records, warning_records, error_records, meta))
    
    # Policy information
    content.append(H3("⚙️ DMARC-Konfiguration", style="color: #343a40; margin: 30px 0 10px 0;"))
    content.append(create_policy_info(meta))
    
    # Records table
    if records:
        content.append(H3("📋 Detaillierte Ergebnisse", style="color: #343a40; margin: 30px 0 10px 0;"))
        content.append(create_records_table(records))
    
    # Error details
    if error_records:
        error_details = []
        for e in error_records:
            error_details.append(
                f"IP: {e['ip']} | Anzahl: {e['count']} | SPF: {e['spf']} | DKIM: {e['dkim']} | Disposition: {e['disposition']}"
            )
        
        content.append(
            Details(
                Summary("🔍 Fehlerdetails anzeigen", style="cursor: pointer; font-weight: bold; margin: 20px 0 10px 0;"),
                Pre("\n".join(error_details), 
                    style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 12px;")
            )
        )
    
    return Div(*content, id="result", style="animation: fadeIn 0.5s ease-in;")

# Add some CSS for better styling
@rt("/style.css")
def stylesheet():
    return Response("""
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
        line-height: 1.6; 
        color: #333;
        background-color: #f8f9fa;
    }
    
    .htmx-indicator { 
        display: none; 
    }
    
    .htmx-request .htmx-indicator { 
        display: inline; 
    }
    
    button:hover {
        background-color: #0056b3 !important;
        transform: translateY(-1px);
        transition: all 0.2s ease;
    }
    
    table {
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    details summary:hover {
        background-color: #e9ecef;
        padding: 5px;
        border-radius: 4px;
    }
    """, media_type="text/css")

if __name__ == "__main__":
    serve()
