from django.shortcuts import render
from django.http import HttpResponse
import xmltodict, json, html, os, hashlib, re, urllib.parse, base64
from collections import defaultdict

# Fonction utilitaire pour vérifier l'authentification
def is_authenticated(request):
    return 'auth' in request.session

# Fonction utilitaire pour générer un hash MD5
def generate_md5(value):
    return hashlib.md5(str(value).encode('utf-8')).hexdigest()

# Fonction utilitaire pour valider un hash
def validate_hash(hashstr):
    return re.match('^[a-f0-9]{32,32}$', hashstr) is not None

# Fonction utilitaire pour charger des fichiers JSON
def load_json_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return f.read()
    return None

# Fonction principale pour générer le rapport PDF
def reportPDFView(request):
    r = {'out': '', 'html': ''}

    # Vérification de l'authentification
    if not is_authenticated(request):
        return render(request, 'nmapreport/nmap_auth.html', r)
    else:
        r['auth'] = True

    # Vérification si un fichier de scan est chargé
    if 'scanfile' not in request.session:
        return HttpResponse('error: scan file not loaded', content_type="text/html")

    try:
        # Lecture du fichier XML
        scanfile = request.session['scanfile']
        scanmd5 = generate_md5(scanfile)
        oo = xmltodict.parse(open(f'/opt/xml/{scanfile}', 'r').read())
        o = json.loads(json.dumps(oo['nmaprun'], indent=4))
    except Exception as e:
        return HttpResponse(f'error: failed to parse scan file - {e}', content_type="text/html")

    # Initialisation des compteurs
    counters = {
        'po': 0, 'pc': 0, 'pf': 0, 'hostsup': 0,
        'ostype': defaultdict(int), 'pi': defaultdict(int), 'ss': defaultdict(int)
    }

    # Collecte des CVEs
    cvehost = get_cve(scanmd5)

    # Table des matières
    toc = '<h3>Table of Contents</h3><div class="container">'

    # Traitement des hôtes
    for ik in o['host']:
        i = ik if isinstance(ik, dict) else o['host']

        # Récupération de l'adresse IP
        saddress = i['address']['@addr'] if '@addr' in i['address'] \
            else next(ai['@addr'] for ai in i['address'] if ai['@addrtype'] == 'ipv4')
        addressmd5 = generate_md5(saddress)

        # Labels et notes
        labelhost = defaultdict(dict)
        noteshost = defaultdict(dict)
        for lf in os.listdir('/opt/notes'):
            m = re.match(f'^({scanmd5})_([a-z0-9]{{32,32}})\.(host\.label|notes)$', lf)
            if m:
                key, value, type_ = m.group(1), m.group(2), m.group(3)
                if type_ == 'host.label':
                    labelhost[key][value] = load_json_file(f'/opt/notes/{lf}')
                elif type_ == 'notes':
                    noteshost[key][value] = load_json_file(f'/opt/notes/{lf}')

        # Initialisation des détails de l'hôte
        hostdetails_html = ''
        portsfound = False
        lastportid = 0
        hostcounters = {'po': 0, 'pc': 0, 'pf': 0}

        if i['status']['@state'] == 'up':
            # Mise à jour de la table des matières
            toc += f'<b>{saddress}</b><br>&nbsp; <a href="#addr{addressmd5}">Port scan</a><br>'
            counters['hostsup'] += 1

            # Étiquette de l'hôte
            labelout = ''
            if scanmd5 in labelhost and addressmd5 in labelhost[scanmd5]:
                labelcolor = labelToColor(labelhost[scanmd5][addressmd5])
                labelout = f'<span class="label {labelcolor}">{html.escape(labelhost[scanmd5][addressmd5])}</span>'

            # Détails de l'hôte
            hostdetails_html += f'<div style="page-break-before: always;">' \
                                f'<h2 id="addr{addressmd5}">{html.escape(saddress)} {labelout}</h2>' \
                                f'<span class="subtitle">Status: {html.escape(i["status"]["@state"])}, ' \
                                f'Reason: {html.escape(i["status"]["@reason"])}, ' \
                                f'TTL: {html.escape(i["status"]["@reason_ttl"])}</span></div>'

        # Traitement des ports
        portdetails_html_tr = ''
        if 'ports' in i and 'port' in i['ports']:
            for pobj in i['ports']['port']:
                p = pobj if isinstance(pobj, dict) else i['ports']['port']
                if p['@portid'] == lastportid:
                    continue
                lastportid = p['@portid']

                # État du port
                state_icon, state_class = '', ''
                if p['state']['@state'] == 'open':
                    state_icon = '<i class="fas fa-door-open green-text"></i>'
                    counters['po'] += 1
                    hostcounters['po'] += 1
                elif p['state']['@state'] == 'closed':
                    state_icon = '<i class="fas fa-door-closed red-text"></i>'
                    counters['pc'] += 1
                    hostcounters['pc'] += 1
                elif p['state']['@state'] == 'filtered':
                    state_icon = '<i class="fas fa-filter grey-text"></i>'
                    counters['pf'] += 1
                    hostcounters['pf'] += 1

                # Service associé au port
                servicename = p['service']['@name'] if 'service' in p and '@name' in p['service'] else ''
                product = html.escape(p['service']['@product']) if 'service' in p and '@product' in p['service'] else '<i>No Product</i>'
                version = html.escape(p['service']['@version']) if 'service' in p and '@version' in p['service'] else '<i>No Version</i>'

                # Construction du tableau des ports
                portdetails_html_tr += f'<tr>' \
                                       f'<td><span class="blue-text">{p["@protocol"]}</span> / <b>{p["@portid"]}</b><br>{servicename}</td>' \
                                       f'<td>{state_icon} {p["state"]["@state"]}</td>' \
                                       f'<td>{product} / {version}</td>' \
                                       f'</tr>'
                portsfound = True

        # Notes de l'hôte
        notesout = ''
        if scanmd5 in noteshost and addressmd5 in noteshost[scanmd5]:
            notesb64 = noteshost[scanmd5][addressmd5]
            notesout = f'<div style="page-break-before: always;">' \
                       f'<h3 id="notes{addressmd5}">Notes for host {saddress}</h3>' \
                       f'{base64.b64decode(urllib.parse.unquote(notesb64)).decode("ascii")}</div>'
            toc += f'&nbsp; &nbsp; &nbsp; &nbsp; <a href="#notes{addressmd5}">Notes</a><br>'

        # CVEs associés à l'hôte
        cveout_html = ''
        if scanmd5 in cvehost and addressmd5 in cvehost[scanmd5]:
            cvejson = json.loads(cvehost[scanmd5][addressmd5])
            cveout = ''.join(
                f'<div><span class="label red">{cve["id"]}</span> {cve["summary"]}<br>' \
                f'<div class="small"><b>References:</b><br>{"<br>".join(cve["references"])}</div></div>'
                for cve in cvejson
            )
            toc += f'&nbsp; &nbsp; &nbsp; &nbsp; <a href="#cvelist{addressmd5}">CVE List</a><br>'
            cveout_html = f'<div style="page-break-before: always;">' \
                          f'<h3 id="cvelist{addressmd5}">CVE List for {saddress}:</h3>{cveout}</div>'

        # Ajout des détails de l'hôte au HTML final
        if portsfound:
            hostdetails_html += f'<table><thead><tr><th>Protocol / Port</th><th>Port State</th><th>Product / Version</th></tr></thead>' \
                                f'<tbody>{portdetails_html_tr}</tbody></table>' \
                                f'{notesout}{cveout_html}'
            r['html'] += hostdetails_html

    # Finalisation de la table des matières
    toc += '</div>'
    r['html'] = toc + r['html']

    # Génération des graphiques Google Charts
    chart_data = {
        'port_status': [['Open', counters['po']], ['Closed', counters['pc']], ['Filtered', counters['pf']]],
        'ports': [[port, count] for port, count in counters['pi'].items()],
        'services': [[service, count] for service, count in counters['ss'].items()]
    }

    r['html'] += generate_charts(chart_data)

    # Pied de page
    r['html'] += '<div style="page-break-before: always;">' \
                 '<div style="text-align:center;padding-top:600px;">' \
                 '<b>Generated by</b><br>' \
                 '<img src="/static/logoblack.png" style="height:60px;" /><br>' \
                 '<a href="https://github.com/Rev3rseSecurity/WebMap">WebMap</a>' \
                 '</div></div>'

    return render(request, 'nmapreport/report.html', r)

# Fonction utilitaire pour générer les graphiques Google Charts
def generate_charts(data):
    charts = []
    for chart_id, rows in data.items():
        chart_data = ', '.join(f'["{row[0]}", {row[1]}]' for row in rows)
        charts.append(f'''
        var data_{chart_id} = new google.visualization.DataTable();
        data_{chart_id}.addColumn("string", "Label");
        data_{chart_id}.addColumn("number", "Count");
        data_{chart_id}.addRows([{chart_data}]);
        var options_{chart_id} = {{
            title: "{chart_id.replace('_', ' ').capitalize()}",
            width: 500,
            height: 300,
            is3D: true,
            chartArea: {{width: "100%", height: "90%"}},
            legend: {{position: "labeled"}}
        }};
        var chart_{chart_id} = new google.visualization.PieChart(document.getElementById("chart_{chart_id}"));
        chart_{chart_id}.draw(data_{chart_id}, options_{chart_id});
        ''')
    return f'''
    <script type="text/javascript" src="https://www.google.com/jsapi?autoload={{'modules':[{{'name':'visualization','version':'1.1','packages':['corechart']}}]}}"></script>
    <script type="text/javascript">
    google.setOnLoadCallback(drawCharts);
    function drawCharts() {{
        {"".join(charts)}
    }}
    </script>
    '''
