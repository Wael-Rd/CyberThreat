import csv, html, json, os, subprocess
from pathlib import Path
OUT=Path('/evidence')/os.environ['LAB_RUN']
results=json.loads((OUT/'results.json').read_text()); events=[json.loads(x) for x in (OUT/'app.jsonl').read_text().splitlines()]
alerts=[]
for mode in ('vulnerable','hardened'):
    def extract(filt,fields,name):
        args=['tshark','-r',str(OUT/f'{mode}.pcap'),'-d','tcp.port==8080,http','-Y',filt,'-T','fields','-E','separator=\t','-E','header=y']
        for field in fields: args+=['-e',field]
        p=subprocess.run(args,capture_output=True,text=True,check=True)
        (OUT/f'{mode}-{name}.tsv').write_text(p.stdout)
        return list(csv.DictReader(p.stdout.splitlines(),delimiter='\t'))
    syn=extract('tcp.flags.syn == 1 && tcp.flags.ack == 0',['frame.time_epoch','ip.src','ip.dst','tcp.dstport'],'syn')
    http=extract('http.request',['frame.number','frame.time_epoch','ip.src','http.request.method','http.request.uri'],'http')
    ports={r['tcp.dstport'] for r in syn if r['tcp.dstport']}
    if len(ports)>=20: alerts.append(dict(mode=mode,rule='SCAN_PORTS',evidence=f'{mode}-syn.tsv',distinct_ports=len(ports),confidence='forte dans ce scénario; un inventaire autorisé peut produire la même alerte'))
    failures=[e for e in events if e['mode']==mode and e['event']=='login_failure']
    if len(failures)>=3 and max(e['time'] for e in failures)-min(e['time'] for e in failures)<=60:
        alerts.append(dict(mode=mode,rule='LOGIN_BURST',evidence='app.jsonl',count=len(failures),confidence='tentatives répétées; ne prouve pas une compromission'))
    for r in http:
        from urllib.parse import unquote_plus
        if "' OR '1'='1" in unquote_plus(r['http.request.uri']):
            alerts.append(dict(mode=mode,rule='SQLI_PATTERN',evidence=f'{mode}-http.tsv',frame=r['frame.number'],confidence='signature pédagogique; succès confirmé séparément par results.json'))
(OUT/'alerts.json').write_text(json.dumps(alerts,indent=2,ensure_ascii=False))
lines=['# Rapport technique','',f"Exécution : {OUT.name}",'','## Périmètre','Deux conteneurs Docker sur réseau internal, cible pédagogique et station de test. Données synthétiques uniquement. Les conteneurs partagent le noyau WSL2 et ne satisfont pas littéralement une exigence de deux VM.','', '## Résultats vérifiés','']
for name,ok in results['checks'].items(): lines.append(f'- {name}: {"PASS" if ok else "FAIL"}')
lines+=['','## Détection','']
for a in alerts: lines.append('- '+json.dumps(a,ensure_ascii=False))
lines+=['','## Analyse et mitigation','', 'Scan : connexions TCP vers de nombreux ports. Réduire les services exposés et détecter les rafales; la protection SQL ne bloque pas le scan.','', 'Connexion : six mots de passe incorrects. Le mode renforcé limite après trois échecs par adresse sur 60 secondes. Une connexion correcte devient aussi bloquée : compromis de disponibilité. En production : limites par compte et adresse, MFA et temporisation; une limite par IP peut pénaliser un NAT.','', 'Injection SQL : la concaténation permet de lire les deux noms synthétiques. Les paramètres SQL empêchent cette lecture en mode renforcé. La signature réseau seule ne démontre pas le succès; results.json compare la réponse.','', 'HTTP en clair : les identifiants synthétiques sont visibles dans le PCAP. En production utiliser TLS; la visibilité réseau se réduit et les journaux deviennent essentiels.','', '## Limites','Règles offline dédiées aux scénarios, pas un IDS de production. Pas de DoS, shell distant ou données réelles. /control est une interface pédagogique de bascule, à retirer en production. Aucun test de TLS/Burp automatisé.','', '## Preuves','PCAP vulnérable/renforcé, scans Nmap XML/TXT, Netcat, champs TShark TSV, événements JSONL, résultats JSON et empreintes SHA256. Voir le guide pour les captures Wireshark et Burp.']
report='\n'.join(lines)+'\n'; (OUT/'rapport.md').write_text(report)
from dashboard import build
(OUT/'dashboard.html').write_text(build(OUT,results,alerts,report))
