# Modèle de menace et topologie

## Actifs et rôles

- Cible : API HTTP pédagogique, comptes fictifs, SQLite en mémoire; aucune information réelle.
- Station : générateur de trafic et analyseur, Nmap/TShark/tcpdump/Netcat/file/YARA.
- Preuves : captures et événements, enregistrés par exécution, empreintes SHA-256.
- MCP : pont local hôte→Docker; interface d'orchestration à commandes fixes.
- Client IA : reçoit les données non fiables, explique les observations, ne décide pas d'une exécution de fichier.

## Frontières

Les conteneurs sont reliés uniquement à un bridge Docker internal, sans publication de ports. Le stockage partagé `/evidence` est un canal volontaire de collecte. `/samples` est monté en lecture seule dans la station. L'hôte WSL2 et son moteur Docker sont de confiance; les conteneurs partagent son noyau. NET_RAW est nécessaire sur la station pour capturer son propre trafic. La capture se fait sur l'émetteur, car un bridge Docker ne diffuse pas tous les paquets unicast à un troisième capteur.

Le build télécharge les outils avec le réseau de l'hôte; ce réseau ne s'applique pas aux conteneurs en fonctionnement. Le test runtime compare une connexion TCP à 1.1.1.1:443 depuis l'hôte et depuis la station. Il n'envoie pas de requête HTTP. Ce contrôle, la configuration internal et l'absence de port publié documentent le périmètre; ils ne prétendent pas empêcher un administrateur hôte d'accéder aux conteneurs.

## Hypothèses testées

| Hypothèse | Vérification |
|---|---|
| Un scan produit beaucoup de ports TCP distincts | PCAP SYN + Nmap XML |
| Plusieurs échecs rapprochés signalent une rafale d'authentification | Source, événements et intervalle ≤60s |
| Une URI peut contenir une tentative d'injection | Décodage URI, motif exact, trame de la requête |
| La concaténation SQL peut exposer plusieurs comptes | Réponse réelle à la tautologie, comparée à une recherche normale |
| Une requête paramétrée empêche cette injection | Aucun compte retourné en phase renforcée; recherche normale préservée |
| Un rate limit freine les essais répétés | 401,401,401 puis 429; effet sur disponibilité documenté |
| Une chaîne dans un fichier peut essayer de piloter l'IA | Fixture inoffensif avec instruction embarquée; aucune fonction générale d'accès fichier ou shell exposée |

## Risques résiduels

Une règle de scan peut détecter un inventaire légitime; les comptes derrière une adresse NAT peuvent subir une limitation collective. La détection SQL est une signature pédagogique, contournable par d'autres formes d'injection. L'API /control est intentionnellement accessible dans le lab. Le triage statique ne constitue pas une analyse comportementale de malware réel. Un modèle peut se tromper ou suivre une instruction contenue dans les données; les outils MCP réduisent sa portée mais ne prouvent pas son invulnérabilité.
