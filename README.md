# NetWatch : surveillance et sécurité du réseau local

Application web **Python / Flask** qui surveille un réseau local : elle détecte les appareils connectés, identifie leur fabricant, scanne leurs ports avec **Nmap**, repère les ports sensibles et génère des alertes de sécurité, le tout visualisé dans un tableau de bord et stocké dans **SQLite**.

## Fonctionnalités

- Détection des appareils connectés au réseau local (IP, adresse MAC, nom d'hôte)
- Identification du fabricant de chaque appareil à partir de l'adresse MAC
- Scan des ports ouverts et des services avec Nmap
- Détection des ports sensibles ou dangereux (Telnet, SMB, RDP, VNC, bases de données exposées, etc.) avec trois niveaux de gravité
- Génération d'alertes de sécurité, y compris à la détection d'un nouvel appareil, sans doublons d'un scan à l'autre
- Tableau de bord : nombre d'appareils, de ports ouverts, d'alertes, niveau de risque par appareil
- Base de données SQLite pour conserver appareils, ports et alertes
- API JSON : `/api/devices` et `/api/alerts`

## Sécurité de l'outil

- Seuls les **réseaux privés** (192.168.x.x, 10.x.x.x, 172.16-31.x.x) peuvent être scannés, avec une taille maximale de /22
- Nmap est lancé sans shell, avec une liste d'arguments, ce qui évite l'injection de commandes
- **Scannez uniquement un réseau qui vous appartient ou pour lequel vous avez une autorisation.**

## Technologies

Python, Flask, Nmap, SQLite, HTML, CSS.

## Structure

```
netwatch/
├── app.py            # application Flask et routes
├── scanner.py        # appels Nmap, validation de la cible, lecture du XML
├── alerts.py         # règles de détection des ports sensibles
├── db.py             # accès SQLite
├── demo.py           # données de démonstration
├── templates/        # page du tableau de bord
├── static/           # feuille de style
└── tests/            # tests unitaires
```

## Installation

1. Installer Python 3.10 ou plus récent et [Nmap](https://nmap.org/download.html).
2. Installer les dépendances :

```bash
pip install -r requirements.txt
```

## Lancer l'application

Mode réel (le fabricant des appareils n'est affiché que si Nmap est lancé avec les droits administrateur/root) :

```bash
python app.py
```

Mode démo, sans réseau ni Nmap, avec des appareils fictifs :

```bash
# Linux / macOS
NETWATCH_DEMO=1 python app.py
# Windows (PowerShell)
$env:NETWATCH_DEMO="1"; python app.py
```

Ouvrir ensuite http://127.0.0.1:5000 et cliquer sur « Lancer le scan ».

Variables d'environnement : `NETWATCH_TARGET` (réseau par défaut, `192.168.1.0/24`), `NETWATCH_DB` (fichier SQLite, `netwatch.db`), `NETWATCH_DEMO` (`1` pour le mode démo).

## Tests

```bash
python -m unittest discover -s tests -t .
```

Les tests couvrent la validation des cibles, la lecture des résultats Nmap, les règles d'alerte et le tableau de bord en mode démo.

## Limites et pistes d'amélioration

- Le scan est synchrone : la page attend la fin du scan
- Pas d'authentification : l'application est prévue pour un usage local (127.0.0.1)
- Pistes : scans planifiés, historique des changements, notifications par e-mail, export CSV

## Auteure

Hanine Maaoui.
