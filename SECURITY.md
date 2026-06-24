# Politique de sécurité

GoaCloud prend la sécurité au sérieux. Ce document décrit comment signaler une
vulnérabilité de manière responsable et ce que vous pouvez attendre en retour.

---

## Signaler une vulnérabilité

**N'ouvrez PAS d'issue publique, de discussion ou de Pull Request pour décrire une
faille de sécurité.** Une issue publique exposerait le problème avant qu'un
correctif ne soit disponible et mettrait en danger les instances déjà déployées.

Utilisez plutôt le canal privé de divulgation responsable de GitHub :

1. Rendez-vous sur l'onglet **« Security »** du dépôt.
2. Cliquez sur **« Report a vulnerability »** (GitHub Security Advisories).
3. Décrivez le problème de façon détaillée (voir ci-dessous).

Ce canal est **privé** : seuls vous et les mainteneurs y avez accès. Aucune
adresse e-mail ni contact personnel n'est nécessaire — tout passe par le mécanisme
de **GitHub Security Advisories** du dépôt.

### Que faire figurer dans votre rapport

Pour accélérer le traitement, incluez si possible :

- une **description claire** de la vulnérabilité et de son impact ;
- les **étapes de reproduction** (preuve de concept, requêtes, configuration) ;
- la **version / le commit** concerné ;
- le **composant** touché (interface web, API Proxmox/Wazuh, worker SOAR, helper
  `goabackup`, gestion de session, etc.) ;
- toute **piste de correctif** ou de contournement, si vous en avez une.

---

## Délais de réponse (indicatifs)

GoaCloud est un projet **pré-1.0 en développement actif**, maintenu sur du temps
limité. Les délais ci-dessous sont des objectifs de bonne foi, non un engagement
contractuel :

| Étape                                   | Objectif indicatif |
| --------------------------------------- | ------------------ |
| Accusé de réception du rapport          | sous **72 heures** |
| Première évaluation / triage            | sous **7 jours**   |
| Correctif ou plan de remédiation        | selon la sévérité  |

Nous vous tiendrons informé de l'avancement via l'advisory privé, et nous
créditerons volontiers les personnes ayant signalé une faille de manière
responsable (sauf demande contraire de leur part) une fois le correctif publié.

---

## Périmètre

### Dans le périmètre

- L'application GoaCloud elle-même : interface web, routage/authentification,
  gestion de session, contrôle d'accès (rôles).
- Les clients d'intégration : API Proxmox, API Wazuh / Wazuh Indexer, worker SOAR,
  bot Discord, enrichissement IA.
- Le **helper `goabackup`** (forced-command côté hôte Proxmox) et son périmètre
  d'opérations.
- Le stockage et le **chiffrement des secrets** en base, la génération/usage de
  `SESSION_SECRET`.
- Les manifestes de déploiement fournis (`Dockerfile`, `docker-compose*.yml`).

### Hors périmètre

- Les **secrets, mots de passe et configurations propres à votre déploiement.**
  GoaCloud est **auto-hébergé** : chaque PME gère et protège ses propres
  identifiants — `SESSION_SECRET`, comptes et chiffrement **MySQL**, jetons
  Proxmox/Wazuh, token Discord, clés d'API IA, certificats TLS. Une fuite ou une
  mauvaise configuration de **vos** secrets n'est pas une vulnérabilité du projet.
- Le **durcissement de l'hôte** sous-jacent (OS, réseau, pare-feu, Proxmox,
  reverse proxy) : c'est la responsabilité de l'opérateur.
- Les **logiciels tiers** intégrés (Proxmox VE, Wazuh, MySQL, Ollama, Discord) —
  signalez ces failles à leurs éditeurs respectifs.
- Les rapports issus uniquement d'un **scanner automatisé** sans impact démontré.
- L'**ingénierie sociale**, le déni de service volumétrique, et les problèmes
  exigeant un accès physique ou des privilèges déjà administrateur sur l'instance.

---

## Modèle de sécurité — rappel

GoaCloud est **souverain, mono-tenant et privacy-by-design** : zéro télémétrie,
zéro phone-home, aucun accès du créateur aux données ou à l'usage des instances.
Cela implique un partage de responsabilités clair :

- **Le projet** est responsable de la correction des vulnérabilités dans le code
  livré (voir « Dans le périmètre »).
- **L'opérateur (la PME)** est responsable de l'exploitation sécurisée de son
  instance : génération d'un `SESSION_SECRET` fort et unique, protection de la
  base MySQL et des secrets qu'elle chiffre, gestion des jetons d'intégration,
  mise à jour de l'hôte et exposition réseau maîtrisée (TLS, reverse proxy,
  filtrage d'accès).

Tenir vos secrets confidentiels et votre instance à jour fait partie intégrante
du modèle de sécurité.

---

## Divulgation coordonnée

Nous suivons une approche de **divulgation coordonnée** : merci de nous laisser un
délai raisonnable pour corriger et publier un correctif avant toute divulgation
publique. Une fois le correctif disponible, un avis de sécurité (GitHub Security
Advisory) pourra être publié pour informer les utilisateurs.
