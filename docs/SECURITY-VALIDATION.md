# Validation de sécurité

Exécution de référence : `run-20261011T224758Z`, 11 octobre 2026. Les tests portent sur ce laboratoire local et ses scénarios synthétiques. Ils ne démontrent pas une impossibilité universelle d’évasion.

## Résultats observés

| Contrôle | Résultat réel |
|---|---|
| Réseau Docker interne, deux services, aucun port publié | PASS |
| Connexion Internet station vers 1.1.1.1:443 | Refusée; connexion de référence depuis l’hôte réussie |
| Service sentinelle sur la passerelle hôte | Accessible depuis l’hôte, refusé depuis les deux conteneurs |
| Système de fichiers racine en lecture seule | Écriture refusée pour cible, station et worker statique |
| Création d’espace de noms mount | Refusée pour les trois acteurs |
| Socket Docker, périphériques hôte, espaces PID/IPC hôte | Absents |
| Seccomp et no-new-privileges | Actifs pour les trois acteurs |
| Cible UID 1000 | Aucune capacité effective |
| Capture station UID 0 | NET_RAW uniquement, masque 0x2000 |
| Triage UID/GID 65534 | Aucune capacité; écriture échantillons et preuves refusée |
| IPv6 dans les deux services | Désactivé |
| Limites mémoire / CPU / PID | Cible 128 MiB / 0,5 / 64; station 384 MiB / 0,75 / 128 |
| MCP : traversée, liens symboliques, artefacts non autorisés, taille excessive | Rejetés dans les tests stdio |
| Protection du bridge absente | Appel de triage refusé; protection restaurée puis appel réussi |
| Chaîne HTML malveillante dans le fichier de formation | Affichée comme texte; aucun script exécuté dans Chromium |

Preuves : `runtime-checks-latest.json`, `sandbox-audit-latest.json`, `dashboard-tests.json` et journaux de validation dans le dossier de référence. Les tests sont rejouables avec les scripts et fichiers `tests/`.

## Frontières de confiance

L’hôte, Docker, le code MCP et l’utilisateur OpenCode sont de confiance. Le MCP s’exécute sur l’hôte et dispose du pouvoir nécessaire pour orchestrer ses propres conteneurs : il n’est pas lui-même une barrière contre un administrateur malveillant. Ses cinq outils utilisent des arguments fixes et des chemins validés; aucun outil shell général n’est exposé. L’agent `lab-analyst` autorise seulement ces outils. Les autres agents et changements manuels de configuration restent sous contrôle de l’utilisateur.

Le filtrage INPUT dédié interdit les nouvelles connexions du bridge vers l’hôte; il conserve les réponses aux connexions initiées par l’hôte. Il ne modifie pas les politiques globales du pare-feu. Le réseau interne et le test de sortie valident la configuration courante, sans constituer une protection contre une faille du noyau.

La collecte autorisée peut écrire dans les preuves. Le worker statique ne peut pas les modifier. Les SHA-256 détectent un changement par comparaison avec un manifeste conservé séparément; ils ne sont pas une signature cryptographique contre un administrateur qui remplace aussi le manifeste.

## Limites explicites

Deux conteneurs partagent le noyau WSL2 : ce ne sont pas deux VM. Aucun malware inconnu n’est exécuté. Le triage inspecte au maximum 10 MiB de données, avec `file`, chaînes, entropie et YARA; un verdict `indeterminate` ne signifie pas « sain ». Les parseurs peuvent eux-mêmes présenter des vulnérabilités. Pour une analyse dynamique de véritable malware, utiliser un environnement VM jetable distinct, sans données personnelles ni passerelle vers ce poste.

Versions observées : Docker 27.5.1+dfsg4, runc 1.3.3+ds1, noyau 6.18.33.2-microsoft-standard-WSL2. runc 1.3.3 est une version corrigée pour les problèmes identifiés dans [l’avis officiel GHSA-9493-h29p-rfm2](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2). Cela n’est pas un audit exhaustif des vulnérabilités ni une garantie d’absence d’évasion. Le noyau ne fournit pas la limite de swap Docker; le plafond mémoire RAM est bien vérifié.

Le test de connexion native OpenCode et les appels SDK MCP ont réussi. Aucune requête à un modèle payant n’a été effectuée : l’interprétation par un LLM reste à démontrer manuellement. Burp Suite Community 2025.10.6-43347 est disponible et son lancement CLI est vérifié; sa session GUI/Repeater reste manuelle. Les captures Wireshark GUI et les interactions du dashboard ont été réellement exécutées.
