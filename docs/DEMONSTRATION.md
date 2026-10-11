# Démonstration : 8 à 10 minutes

1. Présenter le schéma et la différence conteneurs/VM (1 min).
2. Montrer `docker compose ps`, `network.json` et les limites de compose.yaml (1 min).
3. Exécuter `./scripts/lab.sh run`; montrer les vérifications PASS (1 min).
4. Ouvrir le PCAP vulnérable dans Wireshark et montrer le scan (1 min).
5. Montrer les tentatives de connexion et les réponses 401/200, puis 429 dans le PCAP renforcé (2 min).
6. Montrer l'injection et comparer les réponses dans results.json (1 min).
7. Montrer les alertes, expliquer les faux positifs et les recommandations (1 min).
8. Arrêter le lab avec `./scripts/lab.sh down` (30 s).

## Captures d'écran authentiques

Ouvrir le dossier de preuves depuis WSL : `explorer.exe evidence`. Ouvrir les PCAP dans Wireshark Windows; si HTTP n'est pas décodé, sélectionner un paquet TCP port 8080 → Analyze → Decode As → HTTP.

| Capture à enregistrer | Filtre Wireshark / action |
|---|---|
| 01-topologie.png | terminal : compose ps et réseau internal |
| 02-scan.png | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| 03-login.png | `http.request.uri == "/login" || http.response.code == 401` |
| 04-sqli.png | `http.request.uri contains "users"`; Follow TCP Stream |
| 05-protection.png | PCAP renforcé : `http.response.code == 429` |
| 06-resultats.png | dashboard.html et tests PASS |

Les numéros de trame de l'injection sont dans alerts.json. Capturer la liste des paquets ET les détails pertinents; ne pas remplacer une capture réelle par un dessin.

## Burp Suite Community : exercice manuel facultatif

Burp est installé/lancé sur l'hôte, hors budget des conteneurs. Aucun accès navigateur à la cible n'est publié par défaut. Pour une démonstration Burp, créer temporairement `compose.gui.yaml` :

```yaml
services:
  target:
    ports:
      - "127.0.0.1:18080:8080"
```

```bash
docker compose -f compose.yaml -f compose.gui.yaml up -d
```

Ouvrir `http://127.0.0.1:18080/` via le navigateur Burp. Dans Repeater envoyer `GET /users?name=%27+OR+%271%27%3D%271 HTTP/1.1` avec `Host: 127.0.0.1:18080`. Le lab reste dans le dernier mode renforcé après le run. Pour choisir le mode, Repeater : `POST /control`, Content-Type application/json, corps `{"mode":"vulnerable"}` ou `{"mode":"hardened"}`; recalculer Content-Length. Photographier la requête et la réponse comparées. Cet endpoint est uniquement une commande de lab.

Dans certains environnements Docker Engine WSL, le transfert localhost vers Windows nécessite une configuration WSL; utiliser Burp dans WSL ou vérifier l'intégration Docker Desktop. Après l'exercice : `docker compose -f compose.yaml -f compose.gui.yaml down`, puis relancer la configuration par défaut. La publication locale est une exception temporaire à l'isolation; la démonstration automatique n'en dépend pas.

Capture automatique du tableau de preuves réel (Chromium local) : `python3 scripts/screenshots.py evidence/run-<UTC>`. Cela enregistre deux PNG avant/après et recalcule SHA256SUMS. Ces captures montrent le dashboard; les captures Wireshark/Burp du tableau précédent sont des captures GUI supplémentaires pour la présentation.
