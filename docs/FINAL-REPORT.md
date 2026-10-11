# Rapport technique final : Malware Analysis Lab

Projet, laboratoire de détection des cybermenaces. Référence : `run-20261011T224758Z`, 11 octobre 2026.

## Architecture et objectif

Deux conteneurs sur un réseau interne : station `172.31.0.3` et cible HTTP `172.31.0.2:8080`. La station capture son propre trafic. La cible contient uniquement des comptes synthétiques. Les limites cumulées sont 512 MiB de RAM et 1,25 CPU; le moteur Docker et WSL2 consomment des ressources supplémentaires. La mesure au repos des services est environ 33 MiB.

## Analyse fondée sur les preuves

# Rapport technique

Exécution : run-20261011T224758Z

## Périmètre
Deux conteneurs Docker sur réseau internal, cible pédagogique et station de test. Données synthétiques uniquement. Les conteneurs partagent le noyau WSL2 et ne satisfont pas littéralement une exigence de deux VM.

## Résultats vérifiés

- baseline_ok: PASS
- normal_lookup_ok: PASS
- sql_injection_reproduced: PASS
- sql_injection_mitigated: PASS
- rate_limit_mitigated: PASS
- vulnerable_login_succeeded: PASS
- blocked_correct_login: PASS

## Détection

- {"mode": "vulnerable", "rule": "SCAN_PORTS", "evidence": "vulnerable-syn.tsv", "distinct_ports": 101, "confidence": "forte dans ce scénario; un inventaire autorisé peut produire la même alerte"}
- {"mode": "vulnerable", "rule": "LOGIN_BURST", "evidence": "app.jsonl", "count": 6, "confidence": "tentatives répétées; ne prouve pas une compromission"}
- {"mode": "vulnerable", "rule": "SQLI_PATTERN", "evidence": "vulnerable-http.tsv", "frame": "347", "confidence": "signature pédagogique; succès confirmé séparément par results.json"}
- {"mode": "hardened", "rule": "SCAN_PORTS", "evidence": "hardened-syn.tsv", "distinct_ports": 101, "confidence": "forte dans ce scénario; un inventaire autorisé peut produire la même alerte"}
- {"mode": "hardened", "rule": "LOGIN_BURST", "evidence": "app.jsonl", "count": 3, "confidence": "tentatives répétées; ne prouve pas une compromission"}
- {"mode": "hardened", "rule": "SQLI_PATTERN", "evidence": "hardened-http.tsv", "frame": "345", "confidence": "signature pédagogique; succès confirmé séparément par results.json"}

## Analyse et mitigation

Scan : connexions TCP vers de nombreux ports. Réduire les services exposés et détecter les rafales; la protection SQL ne bloque pas le scan.

Connexion : six mots de passe incorrects. Le mode renforcé limite après trois échecs par adresse sur 60 secondes. Une connexion correcte devient aussi bloquée : compromis de disponibilité. En production : limites par compte et adresse, MFA et temporisation; une limite par IP peut pénaliser un NAT.

Injection SQL : la concaténation permet de lire les deux noms synthétiques. Les paramètres SQL empêchent cette lecture en mode renforcé. La signature réseau seule ne démontre pas le succès; results.json compare la réponse.

HTTP en clair : les identifiants synthétiques sont visibles dans le PCAP. En production utiliser TLS; la visibilité réseau se réduit et les journaux deviennent essentiels.

## Limites
Règles offline dédiées aux scénarios, pas un IDS de production. Pas de DoS, shell distant ou données réelles. /control est une interface pédagogique de bascule, à retirer en production. Aucun test de TLS/Burp automatisé.

## Preuves
PCAP vulnérable/renforcé, scans Nmap XML/TXT, Netcat, champs TShark TSV, événements JSONL, résultats JSON et empreintes SHA256. Voir le guide pour les captures Wireshark et Burp.


## Interprétation et mitigations

Le scan révèle une reconnaissance, sans prouver une compromission. Les essais de connexion démontrent une rafale de tentatives. La tautologie SQL montre une exposition de deux noms synthétiques dans la phase vulnérable; la requête paramétrée supprime cette exposition dans la phase durcie. La limitation des échecs produit HTTP 429, avec un compromis visible : un utilisateur légitime peut être temporairement bloqué. En production, combiner limites par compte et source, temporisation, MFA, journalisation et supervision.

Les signatures de détection restent actives après mitigation : elles signalent la tentative même si son effet est empêché. Les seuils sont pédagogiques et ne sont pas une validation de performances sur du trafic réel. Les règles YARA du fixture sont des indicateurs de formation, pas une preuve de malware.

## Extension MCP et livraison

Le serveur MCP expose cinq outils bornés pour lancer le scénario, vérifier l’état, consulter les preuves et effectuer le triage statique. L’intégration native OpenCode est connectée; aucun appel LLM payant n’a été lancé. Les contenus des échantillons sont des données non fiables.

Voir [validation de sécurité](SECURITY-VALIDATION.md), [six semaines](SIX-WEEKS.md), [intégration OpenCode](AI-MCP.md) et [script vidéo](VIDEO-SCRIPT.md). Les [preuves](../evidence/run-20261011T224758Z/dashboard.html) comprennent deux PCAP, les résultats Nmap/Netcat/tcpdump/TShark, journaux, triage, quatre captures PNG et le manifeste SHA-256.

Deux conteneurs constituent une adaptation de l’exigence de deux VM, à faire valider par l’enseignant. Aucune garantie absolue d’absence d’évasion et aucune exécution de malware inconnu ne sont revendiquées.
