# Laboratoire de détection des cybermenaces : progression sur six semaines

Projet · Malware Analysis Lab : AI-assisted Detection.

Ce dossier organise les travaux selon les six étapes du sujet. Les étapes peuvent être reproduites aujourd'hui; aucune affirmation de six semaines réellement écoulées n'est faite. Les résultats techniques sont associés à une exécution horodatée dans `evidence/`.

| Semaine | Travail | Livrable et preuve | Critère de validation |
|---|---|---|---|
| 1 : Préparation | Menaces, rôles, architecture, périmètre | compose.yaml, docs/THREAT-MODEL.md, network.json, runtime-checks.json | Deux conteneurs, réseau internal, limites actives, aucun port publié |
| 2 : Reconnaissance | Hôtes, ports, service HTTP, Netcat | Nmap XML/TXT, Netcat TXT, inventaire dans le rapport | La cible répond sur 8080; ports 1–100 fermés |
| 3 : Trafic | Acquisition intégrale, extraction, comportements | Deux PCAP, HTTP/SYN TSV, captures du dashboard | PCAP lisibles, requêtes HTTP et scan observables |
| 4 : Scénarios | Scan, connexions répétées, SQLi synthétique | run.py, app.jsonl, results.json | Attaques reproduites avec un contrôle normal |
| 5 : Corrélation | Règles, validation, protections, limites | alerts.json, rapport.md, triage.json, contrôles PASS | Trois familles détectées dans chaque phase; SQLi et rafale mitigées |
| 6 : Livraison | Rapport, dossier, intégrité, présentation | dashboard.html, presentation.html, SHA256SUMS, archive du projet, script vidéo | Démonstration rejouable et artefacts vérifiables |

## Travail personnel pour la vidéo

Lire les conclusions, sélectionner les trames mentionnées dans alerts.json et répéter le commentaire oral. Les captures du dashboard sont fournies; les captures GUI Wireshark/Burp peuvent enrichir la vidéo selon docs/DEMONSTRATION.md. Faire valider explicitement le remplacement de deux VM par deux conteneurs.
