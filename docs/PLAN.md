# Plan de réalisation et présentation

Objectif : expliquer une attaque avec des preuves corrélées et démontrer l'effet d'une protection, dans un environnement reproductible et économique.

1. **Cadrage (30 min)** : faire accepter l'adaptation conteneurs/VM; noter le périmètre synthétique, les contraintes WSL et le budget ressources.
2. **Installation (30–60 min)** : vérifier le moteur Docker, construire les deux images, vérifier la santé, l'absence de ports publiés et le réseau interne.
3. **Référence (15 min)** : comprendre GET /, la recherche normale et la connexion; relever les adresses source/cible dans les PCAP.
4. **Expérimentation (45 min)** : exécuter une démonstration; examiner les paquets du scan, les codes HTTP de connexion et l'URI SQLi.
5. **Détection (45 min)** : expliquer chaque règle, son seuil et ses faux positifs; corréler PCAP et événements applicatifs par horodatage/source.
6. **Mitigation (30 min)** : comparer les deux phases, expliquer les requêtes paramétrées et le compromis du rate limiting. Recommander TLS, MFA et réduction des services.
7. **Livraison (45 min)** : PCAP, captures authentiques, rapport, résultats PASS, empreintes; répéter une présentation de 8–10 minutes.

## Traçabilité des exigences

| Exigence | Élément livré | Limite |
|---|---|---|
| ≥2 VM / réseau isolé | Deux conteneurs + network.json | Écart explicite VM/conteneurs à accepter |
| Reconnaissance | Nmap XML/TXT + PCAP SYN | Petit périmètre borné |
| Analyse trafic | tcpdump + TShark + Wireshark manuel | Pas de TLS |
| Attaques contrôlées | Connexions et SQLi synthétiques | Pas de malware/DoS |
| Collecte des preuves | PCAP, JSONL, TSV, SHA256 | Captures GUI Wireshark/Burp à réaliser selon guide |
| Détection / mitigation | Six alertes, comparaison des phases | Détection offline |
| Rapport / démonstration | rapport.md + dashboard + guide | Relire et personnaliser pour la soutenance |

## Structure du rapport à remettre

Page de garde (auteur, établissement, date), objectifs, choix Docker et accord sur l'adaptation, schéma, ressources mesurées, périmètre, méthodes, trois analyses avec captures/numéros de trames, corrélation des preuves, protections avant/après, limites et recommandations, conclusion personnelle, annexes et empreintes. Le rapport généré est une base technique réelle; ajouter le contexte scolaire et les captures Wireshark/Burp.
