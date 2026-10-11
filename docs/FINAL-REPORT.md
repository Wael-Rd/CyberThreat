# CyberThreat : Threat Analysis

# Rapport technique

Exécution : run-20261011T231915Z

## Périmètre
Deux conteneurs Docker sur réseau internal, cible synthétique et station de test. Données synthétiques uniquement. Les conteneurs partagent le noyau WSL2 et ne fournissent pas une isolation de type VM.

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
- {"mode": "vulnerable", "rule": "SQLI_PATTERN", "evidence": "vulnerable-http.tsv", "frame": "345", "confidence": "signature pédagogique; succès confirmé séparément par results.json"}
- {"mode": "hardened", "rule": "SCAN_PORTS", "evidence": "hardened-syn.tsv", "distinct_ports": 101, "confidence": "forte dans ce scénario; un inventaire autorisé peut produire la même alerte"}
- {"mode": "hardened", "rule": "LOGIN_BURST", "evidence": "app.jsonl", "count": 3, "confidence": "tentatives répétées; ne prouve pas une compromission"}
- {"mode": "hardened", "rule": "SQLI_PATTERN", "evidence": "hardened-http.tsv", "frame": "342", "confidence": "signature pédagogique; succès confirmé séparément par results.json"}

## Analyse et mitigation

Scan : connexions TCP vers de nombreux ports. Réduire les services exposés et détecter les rafales; la protection SQL ne bloque pas le scan.

Connexion : six mots de passe incorrects. Le mode renforcé limite après trois échecs par adresse sur 60 secondes. Une connexion correcte devient aussi bloquée : compromis de disponibilité. En production : limites par compte et adresse, MFA et temporisation; une limite par IP peut pénaliser un NAT.

Injection SQL : la concaténation permet de lire les deux noms synthétiques. Les paramètres SQL empêchent cette lecture en mode renforcé. La signature réseau seule ne démontre pas le succès; results.json compare la réponse.

HTTP en clair : les identifiants synthétiques sont visibles dans le PCAP. En production utiliser TLS; la visibilité réseau se réduit et les journaux deviennent essentiels.

## Limites
Règles offline dédiées aux scénarios, pas un IDS de production. Pas de DoS, shell distant ou données réelles. /control est une interface pédagogique de bascule, à retirer en production. Aucun test de TLS/Burp automatisé.

## Preuves
PCAP vulnérable/renforcé, scans Nmap XML/TXT, Netcat, champs TShark TSV, événements JSONL, résultats JSON et empreintes SHA256. Voir le guide pour les captures Wireshark et Burp.

## Synthèse structurée et interface

`evidence-summary.json` contient les métadonnées PCAP, la chronologie HTTP, les ports Nmap et la mesure RAM de fin de scénario. Le dashboard ajoute filtrage, recherche et export JSON. Les contrôles Chromium couvrent les interactions et le caractère inerte des chaînes HTML.

Voir [rapport illustré](reports/CyberThreat-Technical-Report.pdf), [runbook](RUNBOOK.md) et [contrôles de sécurité](SECURITY-VALIDATION.md).
