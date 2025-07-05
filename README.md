# 🛡️ Network Guardian

> Projet de fin d’études (PFE) - Licence en Réseaux, Systèmes et Sécurité  
> Développé par : [Mohcine Touil](https://github.com/touilmohcine1)

## 📌 Présentation

**Network Guardian** est une solution de cybersécurité open-source conçue pour la **détection en temps réel d'activités réseau malveillantes** au sein d'une infrastructure informatique. Le projet inclut la **surveillance sur navigateur via Flask**, l’analyse de paquets, l’envoi d’**alertes Telegram**, la **génération de rapports**, et bien plus.

Il s’agit d’un **IDS (Intrusion Detection System)** simplifié avec intégration possible dans un SOC (Security Operation Center) open source.

---

## 🎯 Objectifs

- Détecter plusieurs types d'attaques : ARP Spoofing, DNS Spoofing, DDoS, Scan réseau.
- Afficher en temps réel les alertes sur une interface web.
- Notifier les administrateurs via **Telegram**.
- Centraliser les données dans une base de données SQLite/PostgreSQL.
- Générer des rapports de sécurité.

---

## ⚙️ Fonctionnalités principales

- 🔍 **Détection ARP Spoofing**  
- 🌐 **Détection DNS Spoofing**  
- 💣 **Détection DDoS**  
- 🕵️ **Détection de Scan réseau**  
- 📊 **Dashboard en temps réel via Flask**
- 📤 **Alertes Telegram**
- 🔐 **Interface sécurisée avec page de connexion**
- 📝 **Rapport PDF automatique**

---

## 🖼️ Interface Web

L’interface est développée en Flask avec un tableau de bord simple et efficace :
- Affichage des logs de détection
- Statistiques en temps réel
- Page de connexion

---

## 📦 Structure du projet

```bash
network_guardian/
├── app.py                 # Serveur Flask principal
├── templates/             # HTML (login, dashboard)
├── static/                # Fichiers CSS/JS
├── detector/              # Scripts de détection
│   ├── arp_detector.py
│   ├── dns_detector.py
│   ├── ddos_detector.py
│   └── scan_detector.py
├── alert/                 # Module d'envoi d'alertes
│   └── telegram_alert.py
├── report/                # Génération de rapport PDF
├── database/              # Gestion de la base de données
│   └── db.py
└── requirements.txt       # Dépendances





