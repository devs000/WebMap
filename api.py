from django.shortcuts import render
from django.http import HttpResponse
import xmltodict, json, html, os, hashlib, re, requests, base64, urllib.parse
from collections import OrderedDict
from nmapreport.functions import *

# Fonction utilitaire pour vérifier l'authentification
def is_authenticated(request):
    return 'auth' in request.session

# Fonction utilitaire pour générer un hash MD5
def generate_md5(value):
    return hashlib.md5(str(value).encode('utf-8')).hexdigest()

# Fonction utilitaire pour valider un hash
def validate_hash(hashstr):
    return re.match('^[a-f0-9]{32,32}$', hashstr) is not None

# Fonction utilitaire pour supprimer un fichier
def remove_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)

# Fonction utilitaire pour sauvegarder des données dans un fichier
def save_to_file(file_path, content):
    with open(file_path, 'w') as f:
        f.write(content)

# Suppression des notes
def rmNotes(request, hashstr):
    if not is_authenticated(request):
        return HttpResponse(json.dumps({'error': 'not authenticated'}), content_type="application/json")
    
    scanfilemd5 = generate_md5(request.session['scanfile'])
    if validate_hash(hashstr):
        file_path = f'/opt/notes/{scanfilemd5}_{hashstr}.notes'
        remove_file(file_path)
        return HttpResponse(json.dumps({'ok': 'notes removed'}), content_type="application/json")
    else:
        return HttpResponse(json.dumps({'error': 'invalid format'}), content_type="application/json")

# Sauvegarde des notes
def saveNotes(request):
    if not is_authenticated(request):
        return HttpResponse(json.dumps({'error': 'not authenticated'}), content_type="application/json")
    
    if request.method == "POST" and validate_hash(request.POST['hashstr']):
        scanfilemd5 = generate_md5(request.session['scanfile'])
        file_path = f'/opt/notes/{scanfilemd5}_{request.POST["hashstr"]}.notes'
        save_to_file(file_path, request.POST['notes'])
        return HttpResponse(json.dumps({'ok': 'notes saved'}), content_type="application/json")
    else:
        return HttpResponse(json.dumps({'error': request.method}), content_type="application/json")

# Suppression d'une étiquette
def rmlabel(request, objtype, hashstr):
    if not is_authenticated(request):
        return HttpResponse(json.dumps({'error': 'not authenticated'}), content_type="application/json")
    
    types = {'host': True, 'port': True}
    if objtype in types and validate_hash(hashstr):
        scanfilemd5 = generate_md5(request.session['scanfile'])
        file_path = f'/opt/notes/{scanfilemd5}_{hashstr}.{objtype}.label'
        remove_file(file_path)
        return HttpResponse(json.dumps({'ok': 'label removed'}), content_type="application/json")

# Attribution d'une étiquette
def label(request, objtype, label, hashstr):
    labels = {'Vulnerable': True, 'Critical': True, 'Warning': True, 'Checked': True}
    types = {'host': True, 'port': True}
    
    if not is_authenticated(request):
        return HttpResponse(json.dumps({'error': 'not authenticated'}), content_type="application/json")
    
    if label in labels and objtype in types and validate_hash(hashstr):
        scanfilemd5 = generate_md5(request.session['scanfile'])
        file_path = f'/opt/notes/{scanfilemd5}_{hashstr}.{objtype}.label'
        save_to_file(file_path, label)
        return HttpResponse(json.dumps({'ok': 'label set', 'label': str(label)}), content_type="application/json")

# Récupération des détails d'un port spécifique
def port_details(request, address, portid):
    if not is_authenticated(request):
        return HttpResponse(json.dumps({'error': 'not authenticated'}), content_type="application/json")
    
    try:
        scanfile = request.session['scanfile']
        oo = xmltodict.parse(open(f'/opt/xml/{scanfile}', 'r').read())
        o = json.loads(json.dumps(oo['nmaprun'], indent=4))
        
        for ik in o['host']:
            i = ik if isinstance(ik, dict) else o['host']
            saddress = i['address']['@addr'] if '@addr' in i['address'] \
                else next(ai['@addr'] for ai in i['address'] if ai['@addrtype'] == 'ipv4')
            
            if str(saddress) == address:
                for pobj in i['ports']['port']:
                    p = pobj if isinstance(pobj, dict) else i['ports']['port']
                    if p['@portid'] == portid:
                        return HttpResponse(json.dumps(p, indent=4), content_type="application/json")
    except Exception as e:
        return HttpResponse(json.dumps({'error': str(e)}), content_type="application/json")

# Génération d'un rapport PDF
def genPDF(request):
    if not is_authenticated(request):
        return HttpResponse(json.dumps({'error': 'not authenticated'}), content_type="application/json")
    
    if 'scanfile' in request.session:
        pdffile = generate_md5(request.session['scanfile'])
        pdf_path = f'/opt/nmapdashboard/nmapreport/static/{pdffile}.pdf'
        remove_file(pdf_path)
        
        os.popen(
            f'/opt/wkhtmltox/bin/wkhtmltopdf --cookie sessionid {request.session._session_key} '
            '--enable-javascript --javascript-delay 6000 http://127.0.0.1:8000/view/pdf/ '
            f'{pdf_path}'
        )
        return HttpResponse(json.dumps({'ok': 'PDF created', 'file': f'/static/{pdffile}.pdf'}), content_type="application/json")

# Récupération des CVE (Common Vulnerabilities and Exposures)
def getCVE(request):
    if not is_authenticated(request):
        return HttpResponse(json.dumps({'error': 'not authenticated'}), content_type="application/json")
    
    if request.method == "POST":
        scanfilemd5 = generate_md5(request.session['scanfile'])
        cveproc = os.popen(f'python3 /opt/nmapdashboard/nmapreport/nmap/cve.py {request.session["scanfile"]}')
        cveout = cveproc.read()
        cveproc.close()
        return HttpResponse(json.dumps({'cveout': cveout}), content_type="application/json")
