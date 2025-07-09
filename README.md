# 🛡️ Network Guardian

> Projet de fin d'études (PFE) - Licence en Réseaux, Systèmes et Sécurité  
> Développé par : [Mohcine Touil](https://github.com/touilmohcine1)

## 📌 Présentation

**Network Guardian** est une solution de cybersécurité open-source conçue pour la **détection en temps réel d'activités réseau malveillantes** au sein d'une infrastructure informatique. Le projet inclut la **surveillance sur navigateur via Flask**, l'analyse de paquets, l'envoi d'**alertes Telegram**, la **génération de rapports**, et bien plus.

Il s'agit d'un **IDS (Intrusion Detection System)** avancé avec intégration possible dans un SOC (Security Operation Center) open source.

---

## 🎯 Objectifs

- Détecter plusieurs types d'attaques : ARP Spoofing, DNS Spoofing, DDoS, Scan réseau.
- Afficher en temps réel les alertes sur une interface web.
- Notifier les administrateurs via **Telegram**.
- Centraliser les données dans une base de données SQLite/PostgreSQL.
- Générer des rapports de sécurité.
- **Système d'authentification sécurisé** avec gestion des utilisateurs et rôles.

---

## ⚙️ Fonctionnalités principales

### 🔍 **Détection ARP Spoofing Avancée**
- **Détection de spoofing MAC** avec validation des changements d'adresses
- **Détection de gateway spoofing** (attaques contre la passerelle)
- **Détection de MAC flooding** (une MAC pour plusieurs IPs)
- **Réduction des faux positifs** avec cooldown et seuils configurables
- **Validation des ARP légitimes** (gratuitous ARP, etc.)
- **Alertes avec niveaux de sévérité** (CRITICAL, HIGH, MEDIUM)

### 🌐 **Détection DNS Spoofing Améliorée**
- **Validation DNS cross-reference** avec serveurs DNS de confiance
- **Détection de cache poisoning** avec historique des réponses
- **Détection d'amplification DNS** (attaques par amplification)
- **Protection contre les domaines sensibles** (banques, services critiques)
- **Détection de spoofing d'IPs internes** pour domaines externes
- **Support des serveurs DNS légitimes** (Google, Cloudflare, OpenDNS)

### 💣 **Détection DDoS Multi-protocoles**
- **Détection de flood TCP/SYN** avec seuils configurables
- **Détection de flood UDP** et ICMP
- **Détection d'attaques par amplification** (ratio packets/destinations)
- **Détection de flood à petits paquets** (attaques de volume)
- **Détection de DDoS à débit lent** (attaques soutenues)
- **Détection de flood multi-protocoles** (TCP + UDP + ICMP)
- **Analyse de taille de paquets** pour détecter les patterns malveillants

### 🕵️ **Détection de Scan Réseau Complète**
- **Détection de scans SYN, FIN, RST, NULL, XMAS**
- **Détection de scans UDP et ICMP**
- **Détection de scans lents** (distribués sur le temps)
- **Détection de scans de ports communs** (21, 22, 80, 443, etc.)
- **Détection de scans mixtes** (plusieurs types simultanément)
- **Filtrage du trafic légitime** (serveurs connus, ports standards)
- **Seuils configurables** par type de scan

### 📊 **Dashboard en temps réel via Flask**
- **Interface moderne et responsive**
- **Graphiques interactifs** avec Chart.js
- **Statistiques en temps réel** des détections
- **Historique des alertes** avec filtres
- **Niveaux de sévérité** colorés

### 📤 **Alertes Telegram**
- **Notifications instantanées** sur Telegram
- **Messages détaillés** avec informations d'attaque
- **Niveaux de priorité** selon la sévérité

### 🔐 **Interface sécurisée avec authentification**
- **Système de rôles** (Admin, Manager)
- **Gestion des utilisateurs** par les administrateurs
- **Sessions sécurisées** avec Flask-Login
- **Hachage des mots de passe** avec Werkzeug

### 📝 **Rapport PDF automatique**
- **Génération de rapports** détaillés
- **Statistiques d'attaques** par période
- **Graphiques et tableaux** de synthèse

---

## 🔐 Système d'Authentification et Rôles

Le système inclut maintenant un système d'authentification complet avec gestion des rôles :

### Rôles disponibles :
- **Admin** : Accès complet, gestion des utilisateurs, toutes les fonctionnalités
- **Manager** : Accès aux dashboards et alertes, pas de gestion d'utilisateurs

### Fonctionnalités d'authentification :
- **Page de connexion** sécurisée
- **Gestion des sessions** avec Flask-Login
- **Protection des routes** - accès restreint selon les rôles
- **Hachage sécurisé des mots de passe** avec Werkzeug
- **Interface utilisateur moderne** et responsive
- **Gestion des utilisateurs** par les administrateurs uniquement

### Utilisateur par défaut :
- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@networkguardian.com`
- **Role**: `admin`

⚠️ **Important** : Changez le mot de passe par défaut après la première connexion !

---

## 🖼️ Interface Web

L'interface est développée en Flask avec un tableau de bord moderne et sécurisé :
- **Page de connexion** avec design moderne
- **Dashboard protégé** avec affichage des logs de détection
- **Statistiques en temps réel** avec graphiques interactifs
- **Gestion des alertes** avec interface améliorée
- **Navigation sécurisée** avec bouton de déconnexion
- **Interface d'administration** pour la gestion des utilisateurs

---

## 🛠️ Installation

1. **Cloner le projet**
```bash
git clone https://github.com/touilmohcine1/network_guardian.git
cd network_guardian
```

2. **Créer un environnement virtuel**
```bash
python3 -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate
```

3. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

4. **Lancement de l'application**

**Mode Silencieux (Par défaut - Pas de sortie console) :**
```bash
python app.py
```

**Mode Verbose (Avec sortie console) :**
```bash
python app.py --verbose
# ou
python app.py -v
```

5. **Accéder à l'interface**
- Ouvrir votre navigateur sur `http://localhost:5000`
- Se connecter avec les identifiants par défaut : `admin` / `admin123`

### Contrôle de la Sortie Console

- **Mode Silencieux** : Aucune sortie console sauf les messages de démarrage et les erreurs
- **Mode Verbose** : Sortie console complète incluant les logs des détecteurs et les informations de débogage
- Utilisez le flag `--verbose` ou `-v` pour activer le mode verbose pour le débogage

---

## 👥 Gestion des Utilisateurs

### Utilisation du script de gestion :
```bash
# Lister tous les utilisateurs
python manage_users.py list

# Ajouter un nouvel utilisateur
python manage_users.py add username email password role

# Supprimer un utilisateur
python manage_users.py delete user_id

# Changer le mot de passe d'un utilisateur
python manage_users.py password username new_password

# Afficher l'aide
python manage_users.py help
```

### Exemples :
```bash
# Ajouter un utilisateur administrateur
python manage_users.py add admin2 admin2@example.com securepass123 admin

# Ajouter un utilisateur manager
python manage_users.py add manager1 manager1@example.com pass123 manager

# Changer le mot de passe de l'admin par défaut
python manage_users.py password admin newsecurepassword
```

---

## 📚 Technologies utilisées

- **Python3**
- **Flask** - Framework web
- **Flask-Login** - Gestion de l'authentification
- **Werkzeug** - Sécurité et hachage des mots de passe
- **Scapy** - Analyse de paquets réseau
- **dnspython** - Résolution DNS et validation
- **SQLite3** - Base de données
- **Telegram Bot API** - Notifications
- **HTML/CSS/JS** - Interface utilisateur
- **Chart.js** - Graphiques interactifs
- **ReportLab** - Génération de rapports PDF

---

## 📦 Structure du projet

```bash
network_guardian/
├── app.py                 # Serveur Flask principal avec authentification
├── manage_users.py        # Script de gestion des utilisateurs
├── migrate_db.py          # Script de migration de base de données
├── templates/             # Templates HTML
│   ├── login.html         # Page de connexion
│   ├── index.html         # Dashboard principal
│   ├── alerts.html        # Page des alertes
│   ├── admin_dashboard.html # Dashboard administrateur
│   ├── manager_dashboard.html # Dashboard manager
│   ├── users.html         # Gestion des utilisateurs
│   ├── add_user.html      # Ajout d'utilisateur
│   └── edit_user.html     # Modification d'utilisateur
├── static/                # Fichiers CSS/JS
│   ├── css/
│   └── js/
├── detector/              # Scripts de détection améliorés
│   ├── arp_detector.py    # Détection ARP avancée
│   ├── dns_detector.py    # Détection DNS avec validation
│   ├── ddos_detector.py   # Détection DDoS multi-protocoles
│   └── scan_detector.py   # Détection de scans complets
├── alert/                 # Module d'envoi d'alertes
│   └── telegram_alert.py
├── report/                # Génération de rapport PDF
├── database/              # Gestion de la base de données
│   └── db.py
├── database.db            # Base de données SQLite
└── requirements.txt       # Dépendances
```

---

## 🔒 Sécurité

### Fonctionnalités de sécurité implémentées :
- **Hachage sécurisé des mots de passe** avec Werkzeug
- **Protection CSRF** intégrée dans Flask
- **Sessions sécurisées** avec Flask-Login
- **Validation des entrées** utilisateur
- **Protection des routes** avec décorateurs `@login_required`
- **Gestion des rôles** avec contrôle d'accès
- **Gestion des erreurs** et messages flash
- **Réduction des faux positifs** dans les détections

### Recommandations de sécurité :
1. **Changez le secret key** dans `app.py` en production
2. **Utilisez HTTPS** en production
3. **Changez le mot de passe admin** par défaut
4. **Limitez les tentatives de connexion** si nécessaire
5. **Surveillez les logs** d'accès
6. **Configurez les seuils** de détection selon votre environnement
7. **Ajoutez des IPs légitimes** dans les détecteurs

---

## 🚀 Utilisation

1. **Démarrage** : Lancez `python app.py`
2. **Connexion** : Accédez à `http://localhost:5000`
3. **Configuration** : Ajustez les seuils de détection si nécessaire
4. **Surveillance** : Surveillez les alertes en temps réel

---

## 🔧 Configuration des Détecteurs

### Seuils configurables dans chaque détecteur :

**ARP Detector** :
- `suspicious_threshold` : Nombre d'activités suspectes avant alerte (défaut: 3)
- `cooldown_period` : Délai entre alertes pour même IP (défaut: 60s)

**DNS Detector** :
- `suspicious_threshold` : Seuil d'activités suspectes (défaut: 2)
- `cooldown_period` : Délai entre alertes (défaut: 120s)
- `cache_timeout` : Durée de vie du cache DNS (défaut: 3600s)

**Scan Detector** :
- `port_scan` : Nombre de ports pour alerte scan (défaut: 10)
- `syn_scan` : Nombre de SYN pour alerte (défaut: 5)
- `time_window` : Fenêtre de détection (défaut: 30s)

**DDoS Detector** :
- `packet_flood` : Paquets/sec pour flood (défaut: 1000)
- `syn_flood` : SYN/sec pour SYN flood (défaut: 500)
- `time_window` : Fenêtre de détection (défaut: 10s)

---

## 📊 Améliorations Récentes

### Version 2.0 - Détecteurs Avancés :
- ✅ **Détection ARP** avec validation gateway et MAC flooding
- ✅ **Détection DNS** avec validation cross-reference
- ✅ **Détection DDoS** multi-protocoles et patterns avancés
- ✅ **Détection de scans** complets avec types multiples
- ✅ **Réduction des faux positifs** avec cooldown et seuils
- ✅ **Système de rôles** (Admin/Manager)
- ✅ **Interface d'administration** pour gestion utilisateurs
- ✅ **Logging avancé** avec niveaux de sévérité
- ✅ **Nouvelles dépendances** (dnspython, ipaddress)

---

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer des améliorations
- Ajouter de nouvelles fonctionnalités
- Améliorer la documentation

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

## 📞 Contact

- **Auteur** : [Mohcine Touil](https://github.com/touilmohcine1)
- **Email** : [votre-email@example.com]
- **GitHub** : [https://github.com/touilmohcine1/network_guardian](https://github.com/touilmohcine1/network_guardian)

---

*Développé avec ❤️ pour la cybersécurité*




