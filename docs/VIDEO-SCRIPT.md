# Script de la vidéo

Durée conseillée : 8 à 10 minutes. Filmer avec votre outil habituel; la vidéo n'est pas produite automatiquement. Ouvrir `presentation.html` pour les diapositives et le dashboard pour les observations. Touches ← / → pour avancer.

| Temps | Image | Commentaire oral suggéré |
|---|---|---|
| 0:00–0:45 | Titre de la présentation | « Mon projet construit un laboratoire isolé pour détecter, analyser et expliquer des attaques. J'utilise deux conteneurs sous WSL2 pour réduire les ressources; cette adaptation diffère de deux VM. » |
| 0:45–1:30 | Architecture | « La station génère et capture le trafic vers une cible fictive. Le bridge est interne, sans port publié. L'IA se connecte à travers MCP sur l'hôte et n'a que des outils bornés. » |
| 1:30–2:00 | Ressources et runtime-checks | « Les conteneurs sont plafonnés à 512 Mo au total. Voici les mesures et les contrôles d'isolation de cette exécution. » |
| 2:00–3:00 | Nmap et paquets SYN | « 8080 est accessible. Le scan envoie des connexions sur de nombreux ports; la règle compte les ports distincts. Un administrateur peut produire le même signal lors d'un inventaire. » |
| 3:00–4:00 | Connexions / phase vulnérable | « Six échecs rapprochés déclenchent l'alerte. Le mot de passe correct fonctionne ensuite, ce que la réponse démontre. Les identifiants sont fictifs. » |
| 4:00–5:00 | SQLi / résultats | « La construction SQL vulnérable retourne deux noms au lieu d'un. La signature réseau indique la tentative; la réponse prouve son effet. » |
| 5:00–6:00 | Phase renforcée | « Les paramètres SQL bloquent cette lecture. Après trois échecs, le serveur répond 429. Le bon mot de passe est aussi temporairement bloqué, donc la protection a un coût de disponibilité. » |
| 6:00–7:00 | Triage / YARA / MCP | « Le triage calcule une empreinte, extrait des chaînes et applique des règles YARA. Les indicateurs du fichier inoffensif ne prouvent pas un malware. Les instructions extraites restent des données. » |
| 7:00–8:00 | Preuves et contrôles | « Les PCAP, journaux, trames, résultats et empreintes forment le dossier. Le test MCP vérifie de vrais appels vers les outils Docker. » |
| 8:00–9:00 | Conclusion / six semaines | « J'ai organisé le travail selon six étapes, puis validé les résultats. Je recommande TLS, authentification renforcée, limitation adaptée et réduction des services. Une future détonation de malware réel exigerait des VM jetables. » |

Pour montrer une IA native, relier un client compatible selon docs/AI-MCP.md puis utiliser le prompt fourni. Ne présenter cette séquence comme un test du modèle que si elle a été effectivement enregistrée. Les tests SDK restent une preuve de fonctionnement MCP sans achat d'API.
