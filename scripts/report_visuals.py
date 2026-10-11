"""Generate explanatory diagrams and data-derived figures, never simulated evidence."""
import csv,html,json,re
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
ASSETS=ROOT/'docs/assets/report'
INK='#20354e';BLUE='#466c99';PALE='#eef3f8';LINE='#b9c9da';AMBER='#ab702e'
def text(x,y,lines,size=20,color=INK,anchor='start'):
    return ''.join(f'<text x="{x}" y="{y+i*(size+9)}" text-anchor="{anchor}" font-family="Arial,sans-serif" font-size="{size}" fill="{color}">{html.escape(line)}</text>' for i,line in enumerate(lines))
def node(x,y,w,h,title,lines=(),color=PALE):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{color}" stroke="{LINE}"/>'+text(x+20,y+35,[title],22)+text(x+20,y+68,lines,17,'#536880')
def arrow(x1,y1,x2,y2,label='',color=BLUE):
    return f'<path d="M{x1} {y1}L{x2} {y2}" stroke="{color}" stroke-width="2.5" fill="none" marker-end="url(#arrow)"/>'+text((x1+x2)/2,(y1+y2)/2-10,[label] if label else [],16,color,'middle')
def svg(name,title,subtitle,body,h=760):
    data=f'''<svg xmlns="http://www.w3.org/2000/svg" width="1400" height="{h}" viewBox="0 0 1400 {h}"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0 0L0 6L7 3Z" fill="{BLUE}"/></marker></defs><rect width="1400" height="{h}" fill="white"/>{text(40,48,[title],28)}{text(40,80,[subtitle],17,'#64758a')}{body}</svg>'''
    (ASSETS/(name+'.svg')).write_text(data)
def generate(run):
    ASSETS.mkdir(parents=True,exist_ok=True)
    run=Path(run);s=json.loads((run/'evidence-summary.json').read_text());r=json.loads((run/'results.json').read_text())
    body=f'<rect x="365" y="235" width="975" height="375" rx="14" fill="#f8fafc" stroke="{LINE}" stroke-dasharray="7 5"/>'
    body+=text(395,274,['Réseau Docker interne / aucune publication de port'],21)
    body+=node(45,300,265,125,'Hôte de confiance',['WSL2 + Docker Engine','MCP local / OpenCode'])
    body+=node(410,335,335,135,'Station d’analyse',['Nmap / dumpcap / TShark','NET_RAW pour la capture'])
    body+=node(930,335,335,135,'Cible HTTP',['Port 8080 / SQLite','UID 1000 / données fictives'])
    body+=arrow(310,365,410,365,'')+arrow(745,402,930,402,'TCP / HTTP')
    body+=node(760,520,330,100,'Dossier de preuves',['PCAP / JSONL / résultats'])
    body+=arrow(580,470,760,555,'Collecte')+arrow(1100,470,1000,520,'Événements')
    body+=text(45,515,['Nouvelles connexions','du bridge vers l’hôte :','refusées par le guard'],18,AMBER)
    body+=text(395,675,['Les services partagent le noyau WSL2. Ce schéma décrit la configuration, pas une isolation de type VM.'],17)
    svg('architecture','Architecture et frontière réseau','Schéma explicatif de la configuration réellement testée.',body)
    body=''
    labels=[('01','Trafic contrôlé',['TCP / HTTP vers la cible']),('02','Capture',['dumpcap / deux PCAP']),('03','Extraction',['TShark / TSV SYN et HTTP']),('04','Corrélation',['JSONL + réponses applicatives']),('05','Validation',['Résultats / alertes / garde réseau']),('06','Restitution',['Dashboard / rapport / MCP'])]
    for i,(n,title,lines) in enumerate(labels):
        x=45+(i%3)*445;y=160+(i//3)*240
        body+=node(x,y,385,150,n+' / '+title,lines)
        if i%3!=2:body+=arrow(x+385,y+75,x+430,y+75)
    body+='<path d="M1130 310V360H237V400" stroke="'+BLUE+'" stroke-width="2.5" fill="none" marker-end="url(#arrow)"/>'+text(50,675,['Une tentative, un indicateur et un effet confirmé sont trois informations différentes.'],21)
    svg('pipeline','Chaîne de traitement des preuves','Du scénario aux observations vérifiables.',body)
    body=''
    xs=[145,500,855,1210];names=['Client OpenCode','Serveur MCP','Station Docker','Preuves locales']
    for x,name in zip(xs,names):
        body+=node(x-115,135,230,85,name,[])
        body+=f'<path d="M{x} 220V650" stroke="{LINE}" stroke-width="2" stroke-dasharray="5 7"/>'
    steps=[(0,1,275,'Appel d’un outil autorisé'),(1,2,350,'Commande fixe / contrôle du guard'),(2,3,425,'Capture ou triage statique'),(3,1,510,'Résultats / artefacts bornés'),(1,0,585,'Réponse avec données non fiables')]
    for a,b,y,label in steps:body+=arrow(xs[a],y,xs[b],y,label)
    body+=text(45,710,['Transport SDK et connexion native testés; aucun appel à un modèle hébergé dans la validation.'],17)
    svg('mcp-sequence','MCP : séquence des appels et limites de confiance','Séquence logique des outils; le modèle reste dans son client.',body,780)
    body=node(45,145,620,430,'Phase vulnérable',['Entrée utilisateur interpolée en SQL'])+node(735,145,620,430,'Phase durcie',['Paramètre lié à une requête SQL'])
    body+=node(90,260,530,90,'Tautologie transmise',['Condition étendue par la concaténation'],'#fff7ec')
    body+=arrow(355,350,355,390)+node(90,400,530,110,'Réponse applicative',['Deux noms synthétiques retournés'])
    body+=node(780,260,530,90,'Tautologie transmise',['Valeur traitée comme donnée'],'#eef3f8')
    body+=arrow(1045,350,1045,390)+node(780,400,530,110,'Réponse applicative',['Liste vide / recherche normale conservée'])
    body+=text(50,640,['Le motif est détecté dans les deux phases. La réponse confirme l’effet ou son absence.'],20)
    svg('sql-mitigation','Injection SQL : comparaison des effets','Données fictives uniquement; résultat confirmé par results.json.',body,710)
    body=node(45,150,1310,135,'Hôte : frontière de confiance',['Administrateur / noyau WSL2 / Docker / serveur MCP'])
    body+=node(90,320,610,225,'Services Docker',['Racine en lecture seule / seccomp','Pas de socket Docker / pas de périphériques hôte','Cible : capacités nulles','Capture station : NET_RAW uniquement'])
    body+=node(740,320,570,225,'Worker statique',['UID/GID 65534 / capacités nulles','Échantillons en lecture seule','Écriture des preuves refusée','Absence du guard : outil refusé'])
    body+=text(50,630,['Limites : noyau partagé, parseurs potentiellement vulnérables, absence de garantie absolue d’évasion.'],19,AMBER)
    svg('trust-boundaries','Isolation et permissions par acteur','Synthèse des contrôles observés; aucun fichier suspect n’est exécuté.',body,710)
    tools=[('Nmap','Inventaire de ports','Nmap XML / TXT'),('Netcat','Vérification HTTP','Réponse du service'),('dumpcap','Capture réseau','PCAP classiques'),('TShark','Extraction des champs','TSV SYN / HTTP'),('Wireshark','Inspection graphique','Captures GUI réelles'),('tcpdump','Lecture hors ligne','Sortie texte des paquets'),('file / YARA','Triage statique','Indicateurs sans exécution'),('OpenCode / MCP','Accès borné aux preuves','SDK et connexion native')]
    body=''
    for i,(name,role,proof) in enumerate(tools):
        x=45+(i%4)*340;y=155+(i//4)*235
        body+=node(x,y,310,190,name,[role,proof])
        body+=f'<path d="M{x+20} {y+130}H{x+270}" stroke="{LINE}"/>'+text(x+20,y+164,['OUTIL '+str(i+1).zfill(2)],13,'#64758a')
    svg('toolchain','Outils et artefacts produits','Carte fonctionnelle des outils; les captures suivantes illustrent leur utilisation réelle.',body,690)
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.edgecolor':'#cad3df','axes.labelcolor':INK,'text.color':INK,'xtick.color':'#52667d','ytick.color':'#52667d','savefig.facecolor':'white'})
    fig,axes=plt.subplots(2,1,figsize=(9,5.4),sharex=True,constrained_layout=True)
    for ax,mode,title in zip(axes,['vulnerable','hardened'],['Avant protection','Après protection']):
        statuses=s['phases'][mode]['login_statuses'];colors=[AMBER if x==429 else BLUE if x==401 else '#6a8e79' for x in statuses]
        ax.bar(range(1,8),[1]*7,color=colors,width=.75)
        for i,value in enumerate(statuses,1):ax.text(i,.48,str(value),ha='center',va='center',color='white',fontsize=14,fontweight='bold')
        ax.set_title(title,loc='left',fontweight='bold');ax.set_ylim(0,1.2);ax.set_yticks([]);ax.spines[['top','right','left']].set_visible(False);ax.set_xticks(range(1,8))
    axes[-1].set_xlabel('Numéro d’essai (7 = mot de passe correct après la rafale)')
    fig.savefig(ASSETS/'login-responses.png',dpi=220);plt.close(fig)
    memory=s['memory_snapshot'];fig,ax=plt.subplots(figsize=(9,3.7),constrained_layout=True)
    for i,m in enumerate(memory):
        ax.barh(i,m['limit_mib'],color='#e7edf4',height=.5);ax.barh(i,m['usage_mib'],color=BLUE,height=.5)
        ax.text(m['usage_mib']+6,i,f"{m['usage_mib']:g} MiB mesurés / {m['limit_mib']:g} MiB maximum",va='center',fontsize=10)
    ax.set_yticks(range(len(memory)),[m['service'] for m in memory]);ax.set_xlabel('Mémoire des services (MiB)');ax.set_xlim(0,430);ax.spines[['top','right']].set_visible(False)
    fig.savefig(ASSETS/'memory-snapshot.png',dpi=220);plt.close(fig)
    # Tool-output views reproduce actual recorded text; they are not fake terminal sessions.
    views={'nmap-output':('Nmap : résultat du scan enregistré',run/'vulnerable-nmap.txt'),'netcat-output':('Netcat : réponse HTTP enregistrée',run/'hardened-netcat.txt'),'tshark-output':('TShark : champs HTTP extraits',run/'hardened-http.tsv'),'mcp-output':('MCP : validation de connexion enregistrée',run/'opencode-validation.txt')}
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-gpu'])
        for name,(title,path) in views.items():
            if not path.exists():continue
            lines=path.read_text().splitlines();content='\n'.join(lines[:18])
            htmlpage=f'''<html><meta charset="utf-8"><style>body{{margin:0;padding:48px;background:#eef2f6;font:20px Arial;color:{INK}}}.card{{background:white;border:1px solid #cbd7e4;border-radius:10px;overflow:hidden}}h1{{font-size:26px;margin:0;padding:28px 32px;border-bottom:1px solid #d9e2ec}}pre{{margin:0;background:#14283f;color:#dce7f4;padding:32px;font:22px monospace;white-space:pre-wrap;line-height:1.7;word-break:break-word}}footer{{padding:22px 32px;font-size:15px;color:#536880}}</style><div class="card"><h1>{html.escape(title)}</h1><pre>{html.escape(content)}</pre><footer>Vue de l’artefact réel : {html.escape(path.name)} · {html.escape(run.name)}</footer></div></html>'''
            page=browser.new_page(viewport={'width':1400,'height':700});page.set_content(htmlpage);page.locator('.card').screenshot(path=str(ASSETS/(name+'.png')));page.close()
        browser.close()
    (ASSETS/'provenance.json').write_text(json.dumps({'reference_run':run.name,'diagrams':'Explanatory diagrams of implemented architecture, not screenshots.','plots':'Derived from results.json and evidence-summary.json.','tool_output_views':'Rendered views of the recorded text artifacts; not GUI screenshots.','wireshark':'Actual GUI captures in the reference evidence directory.'},indent=2))
    print('Generated six architecture/process diagrams, two data plots and recorded tool-output views')
if __name__=='__main__':
    import sys
    generate(sys.argv[1])
