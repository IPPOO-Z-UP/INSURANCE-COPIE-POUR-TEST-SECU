# IPPOO ASSURANCE — État du projet & checklist production

> Document vivant. Mis à jour à chaque session de travail.
> Dernière mise à jour : **2026-05-30** (batch F21→F30 — attestation+SW cache, KYC FIFO+lock, sinistres orphelins, souscription agent, drawer inbox, alertes Overview, audit exports SHA-256, broadcast visibilité, toggle auto-débit admin, cron reminders auto)

---

## 1. Vue d'ensemble

Plateforme de micro-assurance pour le Bénin (cible : informels, commerçants, familles).
Stack : **React + Tailwind v4 + React Router v7** (frontend) / **Supabase Edge Function (Hono, Deno)** + KV store `kv_store_752d1a39` (backend) / **Supabase Realtime Broadcast** (push temps réel) / **Supabase Storage** (pièces jointes).

Trois surfaces :
- **Site public** (`/`, `/devis`, `/sinistre`, …) — vitrine + tunnel de devis.
- **Espace client** (`/espace-client/*`) — application authentifiée façon PWA mobile-first.
- **Back-office admin** (`/espace-client/admin`) — auth séparée par identifiants HMAC, isolée de Supabase Auth.

Tarif unique : **500 FCFA / jour × 31 jours = 15 500 FCFA / mois** pour les 11 micro-assurances.

---

## 2. Travaux réalisés

### 2.1 Catalogue produit
- 11 offres alignées avec le site public, tarif unique 15 500 FCFA/mois, image Unsplash dédiée (toutes différentes, références africaines valorisantes).
- Renommage « Transport » → **« Micro-Assurance Automobile »** (voitures particulières + utilitaires).
- Page Souscription : bannière image avec dégradé blanc haut/bas, icône + badge catégorie en overlay, bouton « Voir les détails » + bouton « Souscrire ».

### 2.2 Messagerie temps réel (client ↔ conseiller)
- Canal Supabase Realtime `chat:<userId>` avec events `message:new`, `message:read`, `message:update`, `typing`, présence.
- Côté serveur : broadcast émis dans `POST /messages`, `POST /messages/attachment`, `POST /admin/messages/:uid` (texte + pièce jointe).
- Auteur conseiller masqué côté client : affiche systématiquement « Service client ».
- Input message : `<textarea>` auto-resize (max 200 px), Entrée = retour ligne, bouton Envoyer obligatoire.
- FAB WhatsApp masqué sur `/espace-client/messagerie` (évite chevauchement avec Envoyer).
- Admin Messagerie : scroll panneaux corrigé (grid `h-[calc(100vh-180px)]`, listes `min-h-0 overflow-y-auto`), dédoublonnage défensif des conversations + thread pour éliminer les warnings React `duplicate key`.

### 2.3 Notifications style push (✅ session du 2026-05-29)
- **Serveur** : helper `setNotifications(uid, list)` qui persiste KV **et** diffuse l'entrée fraîche sur le topic `notifications:<uid>` event `notif:new`. Câblé sur :
  - signup welcome
  - souscription confirmée
  - sinistre déclaré + statut sinistre mis à jour
  - effets de paiement (cotisation, renouvellement, carte activée, mensuel)
  - cycle de facturation mensuel
  - alerte échéance contrat
  - message conseiller (texte + pièce jointe)
  - broadcast admin
  - suppression de compte programmée
- **Client** : composant `NotificationsRealtime` monté dans `ProtectedShell`. Écoute le canal, dédoublonne par `id`, invalide la query React-Query (`qk.notifications`), affiche un toast push-style via `appToast`, joue un **ding 2 tons WebAudio** + **vibration `[60,40,120]` ms**, et déclenche une **Notification système native** (avec `vibrate` + `silent:false`) quand l'onglet est en arrière-plan et la permission accordée.

### 2.4 PWA / Service Worker
- `src/sw.ts` (Workbox) — précache assets, NetworkFirst navigation, StaleWhileRevalidate images, CacheFirst fonts Google.
- **Edge Function exclue du cache SW** (fix « Failed to fetch » sur cold start) : les appels `/functions/v1/` vont toujours au réseau.
- **Cleanup runtime** (`pwa.ts › purgeBrokenSW`) : à la première ouverture après déploiement, désenregistre l'ancien SW et purge les caches `ippoo-api/nav/supabase` (flag `localStorage` `ippoo:sw:purged:v1` empêche la répétition). Nécessaire car `vite build` est interdit dans Make — le SW prébuild ne peut pas être régénéré.
- `push` event handler : prêt à recevoir des Web Push VAPID.

### 2.4.bis Onboarding d'introduction pré-auth (✅ session du 2026-05-29)
- Nouvelle page `/espace-client/decouverte` (`IntroOnboardingPage.tsx`) montrée à la **première ouverture** de l'app cliente, **avant** la connexion.
- 5 phases structurées : Bienvenue → 11 offres → Paiement Mobile Money → Bénéficiaires → Sécurité 100%.
- Interactions : swipe (pointer events, seuil 48 px), flèches clavier, Entrée pour avancer, Escape = skip. Animations Motion direction-aware, dégradés de fond animés, dots de progression, bouton Passer + lien « Déjà inscrit ? ».
- Persistance : flag `localStorage` `ippoo:intro:seen:v1`. Le helper exporté `hasSeenIntro()` est utilisé par `ConnexionPage` pour rediriger les nouveaux visiteurs vers `/decouverte` (l'utilisateur déjà connecté est redirigé vers `/espace-client`).
- N'écrase **pas** la `OnboardingPage` post-inscription (configuration profil / bénéficiaires) qui reste sur `/espace-client/onboarding`.

### 2.4.ter App des conseillers `/agent` — Sprint 1 (✅ session du 2026-05-29)
- Nouvelle surface `/agent` distincte de `/admin` (HMAC) et de l'espace client. **Auth Supabase classique** + gating par rôle `user_metadata.role === "agent"` (ou bootstrap via env var `AGENT_EMAILS` séparée par virgules — emails autorisés pour démarrer avant qu'on ait une UI admin pour assigner les rôles).
- **Serveur** (helpers + routes ajoutés dans `index.tsx`, rev `2026-05-29-02`) :
  - `requireAgent(c)` — vérifie token Supabase + rôle + fallback `AGENT_EMAILS`.
  - `GET /agent/me` — renvoie `{ isAgent, agent: { id, username, email } }` pour gater l'UI.
  - `GET /agent/messages?q&status&mine` — liste de toutes les conversations clients (miroir de `/admin/messages`).
  - `GET /agent/messages/:uid` — lit le thread + marque les messages user comme lus.
  - `POST /agent/messages/:uid` — réponse, broadcast sur `chat:<uid>` + `admin:chat`, notification + push client.
  - `PATCH /agent/messages/:uid/meta` — change statut / assignee / tags ; supporte `{ claim: true }` (auto-assign à soi) et `{ release: true }`.
- **Frontend** :
  - `src/app/agent/AgentLayout.tsx` — provider + role guard (appelle `/agent/me`, redirige sinon).
  - `src/app/agent/api.ts` — wrappers typés (`agentApi.conversations`, `.conversation`, `.reply`, `.updateMeta`, `.me`).
  - `src/app/agent/pages/AgentInboxPage.tsx` — inbox 2 colonnes : recherche + filtres status + checkbox « Mes conv. » à gauche, thread + bouton « Prendre » + sélecteur de statut + input réponse (⌘+Entrée) à droite. Abonnement Realtime au topic partagé `admin:chat` (live updates entre admin et agents).
  - Identité visuelle bleu nuit pour bien démarquer du client (rouge/orange) et de l'admin (clair).
  - Toggle « En ligne / En pause » dans le header (placeholder UI pour le futur dispatch automatique).
- **Routes** (`src/app/routes.ts`) : `/agent` → `AgentLayout` → `AgentInboxPage` en index.
- **Bootstrap d'un conseiller** : créer un user Supabase normal, puis soit (a) renseigner son email dans la secret `AGENT_EMAILS=alice@ippoo.bj,bob@ippoo.bj`, soit (b) updater son `user_metadata.role` à `"agent"` via le dashboard Supabase. Aucun nouveau secret obligatoire — sans `AGENT_EMAILS` seul le rôle compte.

### 2.4.quater App des conseillers `/agent` — Sprint 2 (✅ session du 2026-05-29)
- **Serveur** (rev `2026-05-29-03`) :
  - `GET /agent/claims` — liste agrégée de tous les sinistres (parcourt `claim:*`), enrichis avec nom/email/numéro de membre.
  - `POST /agent/claims/:userId/:claimId/status` — change le statut (`soumis|en_cours|en_examen|valide|rejete|regle`), enregistre `decidedBy` + `decidedAt` + `adminNote`, notifie le client (notification + push).
  - `GET /agent/customer/:uid` — fiche 360° (profil, contrats, sinistres, paiements, bénéficiaires, documents, 20 derniers messages, meta conversation, paramètres, compteur notifs non lues) en `Promise.all` parallèle.
- **Frontend** :
  - `src/app/agent/api.ts` étendu (`agentApi.claims`, `.updateClaimStatus`, `.customer360`) + types `AgentClaim`, `Customer360`.
  - `src/app/agent/pages/AgentClaimsPage.tsx` — 2 colonnes (liste filtrable status + recherche / détail avec note + boutons Valider/En cours/Réglé/Rejeter + lien « Fiche client »).
  - `src/app/agent/pages/AgentCustomerPage.tsx` — fiche client 360° : carte d'identité + KPI strip + 6 sections (contrats, sinistres, paiements, bénéficiaires, documents, derniers messages).
  - `AgentLayout` : nav tabs Inbox / Sinistres (NavLink actif).
- **Routes** : `/agent/sinistres` → `AgentClaimsPage`, `/agent/clients/:uid` → `AgentCustomerPage`.

### 2.4.quinquies App des conseillers — Matricule + Sprint 3 KYC + Templates (✅ session du 2026-05-29)
- **Matricule unique conseiller** (rev `2026-05-29-04` → `06`) :
  - Format `IPPOO-A-XXXX` (4 chiffres), généré à la 1ʳᵉ connexion via `resolveAgentMatricule()`. Persistance KV double : `agent:matricule:<userId>` ↔ `agent:matricule-claim:<mat>` (sentinelle d'unicité, retry bounded sur collision aléatoire).
  - Inclus dans la payload `agent` (`/agent/me`) et exposé partout côté serveur : `author` des messages, `assignee` des conversations (`claim:true`), `decidedBy` + `decidedByMatricule` des sinistres et KYC, clé `by` des audits.
  - Affiché en pill bleue dans le header `AgentLayout`.
- **Sprint 3 — KYC / validation identité** (rev `2026-05-29-05`) :
  - `POST /kyc` (client soumet : `type`, `fields`, `docs`), `GET /kyc` (lecture). Modèle `kv:kyc:<userId>` → `{ current, history }` ; une seule demande active.
  - `GET /agent/kyc` (file `pending` + 30 dernières `decided`), `POST /agent/kyc/:userId/:kycId/decision` (valide/rejete + note motivée). Validation marque `profile.kycVerified = true`, rejet retourne le motif au client (notif + push).
  - Page `src/app/agent/pages/AgentKycPage.tsx` : 2 colonnes (tabs En attente / Décidées + recherche + détail champs/docs + textarea note + boutons Valider/Rejeter). Onglet KYC dans le header.
- **Lien Inbox → Fiche 360°** : bouton « Fiche client » dans le header du thread Inbox, navigation `/agent/clients/:uid`.
- **Templates de réponse rapide** (CRUD perso, rev `2026-05-29-06`) :
  - `GET/POST/PATCH/DELETE /agent/templates[/:id]` — 30 max par conseiller. KV `agent:templates:<matricule>` (clé sur matricule = stable même si le compte est réassigné).
  - UI Inbox : bouton « Templates » au-dessus du textarea ouvre un popover (liste cliquable pour insérer dans la réponse + mode « Gérer » avec création/suppression inline).
- **Routes** : `/agent/kyc` → `AgentKycPage`.

**Sprints restants pour l'app agent** : tâches/rappels, métriques perso, mode terrain (souscription mobile + Mobile Money).

### 2.4.sexies App des conseillers — Souscription assistée + KYC docs (✅ session du 2026-05-29)
- **T6 — Souscription assistée par conseiller** (rev `2026-05-29-16`) :
  - `POST /agent/subscribe/:uid` — crée un contrat pour le compte d'un client, marqué `subscribedBy: matricule` + `subscribedByName`, notifie le client (canal `system`) et audite `agent.contract.subscribe`. Fréquences acceptées : `mensuel|trimestriel|annuel`.
  - UI : bouton `FilePlus2` dans le header de `AgentCustomerPage` ouvre un modal produit/fréquence/note.
  - Badge **« ID VÉRIFIÉE »** affiché sur la fiche client si `profile.kycVerified`.
- **KYC docs signés** (rev `2026-05-29-15`) : bucket dédié `make-752d1a39-kyc`, route `POST /kyc/upload` (multipart, 10 MB, PDF/images) + `GET /kyc/url` (signed 5 min, scopé `${userId}/`). L'enrich `/agent/kyc` signe à la volée chaque document avant rendu.

### 2.4.duodecies Batch harmonie & prod H1-H4 + P2/P4/P5 (✅ session du 2026-05-29)
- **H1 — Filtre « Mes sinistres » côté agent** : toggle dans `AgentClaimsPage` (filtre sur `assignedTo === me.matricule`) + badge « Moi » / matricule sur chaque carte. `AgentClaim.assignedTo/assignedAt/assignedBy` ajoutés au type ; alimenté par le spread `...cl` de `GET /agent/claims`. Matricule pris du contexte d'outlet déjà exposé par `AgentLayout`.
- **H2 — Conseiller attitré visible côté client** : `SinistresPage` affiche un chip rouge « Conseiller IPPOO-A-XXXX » + bloc note conseiller (ambre) sur chaque carte. Champs `assignedTo`, `adminNote`, `decidedAt`, `decidedBy` ajoutés à `interface Claim`.
- **H3 — Lock KYC concurrent** : déjà couvert (`POST /agent/kyc/.../decision` et `POST /admin/kyc/.../decision` retournent 409 si `status !== "pending"`). Pas de nouveau code, validation explicite documentée.
- **H4 — Broadcast `claim:reassign`** : ajouté dans `POST /admin/claims/:userId/:claimId/reassign` (canal `agent:inbox`, event `claim:reassign`) + dans `POST /admin/dispatch/sweep` (events `claim:reassign` et `conv:reassign`). Permet aux consoles agent ouvertes de rafraîchir la liste sans poll.
- **P2 — Mutations bénéficiaires + profil offline** : `updateMe`, `createBeneficiary`, `deleteBeneficiary` wrappées dans `apiOrQueue` (`espace-client/api.ts`). Optimistic UI + repush par la queue persistante.
- **P4 — SLA chip 48 h** : composant `SlaChip` sur chaque carte sinistre client. Vert > 6 h restantes, ambre < 6 h, rouge si dépassé (affiche l'overage en heures). Engagement opposable côté conseiller.
- **P5 — Page statut public `/statut`** : `src/app/components/StatutPage.tsx`, route publique. Poll `/health` toutes les 30 s, affiche état global + ligne par intégration (Kkiapay, Resend, Termii, VAPID, TOTP admin) + latence + rev. Pas d'auth requise.

### 2.4.octies Features F6-F9 batch (✅ session du 2026-05-29)
- **F6 — Notifs agent realtime** : helper `broadcast("agent:inbox", ...)` émis côté serveur dans `POST /claims`, `POST /messages`, `POST /messages/attachment`, `POST /kyc`. Composant `AgentInboxNotifier.tsx` monté dans `AgentLayout`, gating sur l'état `online` (ne sonne pas en pause) : ding WebAudio 2 tons + toast Sonner avec action de navigation + invalidation React-Query (`conversations`/`claims`/`kyc`). Dédupe par event ID, cap 300 entrées.
- **F7 — Tab Admin Agents** : déjà livré dans Sprint 2.4.quinquies (`AgentsTab` complet : CRUD, présence, portefeuilles, rebalance).
- **F8 — Admin KYC + réassignation sinistres** : 3 nouvelles routes (`GET /admin/kyc`, `POST /admin/kyc/:userId/:kycId/decision`, `POST /admin/claims/:userId/:claimId/reassign`). Nouvel onglet **KYC** dans le back-office (`KycTab` 2 colonnes : file pending/decided + détail + Valider/Rejeter avec note motivée). Sélecteur **« Réassigner »** ajouté sur chaque carte sinistre dans `ClaimsTab` — liste les agents actifs (non bannis) via `api.adminListAgents`, déclenche `api.adminReassignClaim` qui notifie en push le nouveau matricule. Sentinelle `decidedBy: "Admin · ${username}"` pour distinguer des décisions agents.
- **F9 — KPIs business + perf agent** : 2 nouvelles routes admin :
  - `GET /admin/kpi` — CA mensuel 12 mois (revenus, souscriptions, résiliations), top 8 produits par CA, croissance MoM, taux de conversion (devis→contrat), taux de churn (résiliés/(actifs+résiliés)), taux d'adoption (membres avec contrat actif), souscriptions assistées par conseiller.
  - `GET /admin/agents/performance?days=N` — fenêtre glissante 7/30/90 j, agrège par matricule : sinistres décidés/validés/rejetés/réglés, contrats souscrits/renouvelés/résiliés, KYC tranchés, paiements encaissés, messages envoyés, **temps de réponse moyen** (pairing user/conseiller avec fenêtre < 7 j).
  - UI : `BusinessKpiWidget` ajouté à `OverviewTab` (5 tuiles KPI + BarChart double-axe CA/souscriptions/résiliations + top produits avec barres de proportion). `AgentPerformanceWidget` ajouté en tête de `AgentsTab` (table triée par charge avec sélecteur de période 7/30/90 j).

### 2.4.undecies Feature F12 — Export comptable + commissions (✅ session du 2026-05-29)
- **`GET /admin/export/accounting?month=YYYY-MM`** : CSV `text/csv` de tous les paiements confirmés du mois — date, userId, email, paymentId, produit, méthode, montant, statut, agent collecteur (username + matricule), taux commission, commission XOF. En-tête commenté (`# CA total / commissions totales / généré par`) + audit `admin.export.accounting`.
- **`GET /admin/export/commissions?month=YYYY-MM`** : CSV agrégé par matricule (paiements collectés, CA, commission due). Pour transmission paie / virement conseillers. Audit `admin.export.commissions`.
- **Taux configurable** : env `COMMISSION_RATE_AGENT` (défaut `0.05`, soit 5%).
- **UI admin** : tuile « Export comptable mensuel » dans `OverviewTab` (sélecteur `<input type="month">` + 2 boutons « Comptable » / « Commissions »). Les CSV sont téléchargés en blob via `api.adminDownloadAccountingCsv` / `api.adminDownloadCommissionsCsv` (X-Admin-Token + `Content-Disposition: attachment`).

### 2.4.decies Feature F11 — Mode hors-ligne client (✅ session du 2026-05-29)
- **Queue d'actions persistante** (`src/app/espace-client/offlineQueue.ts`) : stocke les mutations dans `localStorage` (`ippoo:offline:queue:v1`), expose `enqueue`, `replay`, `subscribe`, `startOfflineQueueLoop`. Retry borné à 5 tentatives, replay déclenché sur `window.online` + tick 30 s + bouton manuel. Les 4xx sont abandonnées silencieusement (action illégale), les 5xx restent en file.
- **Helper opt-in** : `apiOrQueue<T>(path, { method, body, token, label, optimistic })` dans `supabaseClient.ts` — tente le call ; si offline ou échec réseau, enfile et résout avec la valeur optimiste.
- **Bannière persistante** `OfflineBanner.tsx` montée dans `EspaceLayout` (au-dessus du nav bottom). Rouge si hors-ligne (compteur d'actions), ambre si online avec actions en attente (bouton Sync manuel).
- **Wiring initial** : `api.sendMessage` câblé sur `apiOrQueue` — le message s'affiche localement immédiatement et part dès le retour de connexion. Le helper est dispo pour câbler progressivement les autres mutations (profile, bénéficiaires, etc.) sans toucher à l'infra.

### 2.4.nonies Features F10 — Dispatch auto + détection absence (✅ session du 2026-05-29)
- **Auto-assign à la création d'un sinistre** : `POST /claims` appelle `pickOnlineAgentMatricule()` (round-robin existant sur la présence) et stamp `assignedTo`/`assignedAt`/`assignedBy: "system:auto"`. Push notification au matricule choisi (canal `assignment`).
- **Sweep d'absence** : `POST /admin/dispatch/sweep` (body `{ hours: 4 }`) détecte les matricules dont la dernière présence est offline OU stale > 90 s ET dont le `at` < cutoff (hours). Réassigne en round-robin toutes les `conv:meta:*` (assignee) + les sinistres ouverts (`status ∉ {regle, rejete}`) vers les agents en ligne. Stamp `reassignedFrom`/`reassignedBy: "admin-sweep:<username>"` + audit `claim.reassign` + push au repreneur.
- UI admin : nouvelle tuile « Dispatch automatique — sweep des absents » dans `OverviewTab` (à côté de Rappels et Cycle de prélèvement). Bouton « Redistribuer » qui appelle le sweep et affiche le bilan en toast.

### 2.4.septies Features F1-F5 batch (✅ session du 2026-05-29)
- **F1 — Page client KYC** : `/espace-client/verification-identite` (`KycPage.tsx`) — sélecteur de type (identité/adresse/revenu), champs dynamiques, upload jusqu'à 6 pièces, statut courant + historique. Entrée ajoutée dans RAIL `AppShell` + `CommandPalette`.
- **F2 — Pièces jointes sinistre (propagation)** : `/agent/claims` et `/admin/claims` enrichissent désormais chaque `attachment` avec URL signée 5 min. Vue admin (`AdminPage` ClaimsTab) affiche les pièces en chips cliquables au lieu d'un simple compteur.
- **F3 — Bandeau renouvellement Dashboard client** : composant `RenewalBanner` détecte les contrats actifs expirant ≤30 j, tri par urgence, CTA pointant vers `/espace-client/contrats` (où le flow KkiaPay/MoMo existe via `api.renewContract`). Style rouge ≤7 j, orange sinon.
- **F4 — UI Parrainage** : carte `ReferralSection` dans `ParametresPage` — affiche le code, compteur de filleuls, boutons Copier + Partager (Web Share API + fallback clipboard).
- **F5 — Export RGPD** : carte `ExportSection` dans `ParametresPage` — bouton « Télécharger mes données » qui appelle `/account/export` et déclenche le download d'un JSON daté.

### 2.5 UX & navigation
- Logo header : non cliquable en `appMode`, redirige vers le site dans un nouvel onglet sinon (`target="_blank"`).
- FAB d'aide rapide (WhatsApp / urgence / sinistre / devis).
- Toaster Sonner customisé (icône colorée, action button, blur, ombre).
- `appToast` : wrapper avec navigation (action `to`) et types success/error/warn/info.

### 2.4.terdecies Traçabilité enrôlement client → conseiller (F13, ✅ session du 2026-05-30)
- **Question d'origine** : « comment on arrive à savoir quel agent à enroller quel client ? » → Aucune attribution `profile.enrolledBy` n'existait, seulement `payment.collectedBy`, `claim.assignedTo`, `conv:meta.assignee`. Comblé en 4 sous-features.
- **F13a — Backend capture** :
  - `SignupSchema` accepte `enrollerMatricule?` (zod, ≤40). Le handler `POST /signup` valide via `agent:matricule-claim:<mat>` → uid, vérifie non-`banned`, puis pose `enrolledBy / enrolledByUid / enrolledAt / enrolledSource = "invite-link"` sur le profil et `pushAgentNotif` à l'enrôleur.
  - Nouveau `POST /agent/clients` (auth `requireAgent`) : crée un compte client (Supabase `admin.createUser` + `email_confirm: true`), refus si email déjà utilisé avec disambiguation agent/client, attribue `enrolledBy = r.agent.matricule`, `enrolledSource = "agent-console"`, retourne `{ userId, memberNumber, email }`.
- **F13b — Inscription publique capte `?ref=`** :
  - `InscriptionPage` lit `searchParams.get("ref")` et l'injecte dans `signUp({ enrollerMatricule })`. `AuthContext.signUp` forwarde dans le body.
  - Chip visible « Invité par le conseiller IPPOO-A-XXXX » si `?ref` présent.
- **F13c — Console agent : enrôlement direct + lien d'invitation** :
  - `AgentPortfolioPage` : carte gradient avec « Créer un compte » (modal `CreateClientModal` — nom/email/téléphone + mot de passe auto-généré 10 chars) appelant `agentApi.createClient`, et « Copier le lien » → `${origin}/inscription?ref=${matricule}`.
- **F13d — Admin réattribution + KPI enrollments** :
  - `GET /admin/members` expose `enrolledBy / enrolledAt / enrolledSource`. `MembersTab` affiche « Enrollé par : … » sur chaque ligne + bouton « Enrôleur » (`EnrollerReassignButton`) ouvrant un modal qui appelle `PATCH /admin/members/:userId/enroller` (vide = détacher). Audit `enrollment.reassigned`, notif au nouvel enrôleur.
  - `GET /admin/agents/performance` agrège `enrollmentsTotal / enrollmentsWindow` via `profile:<uid>.enrolledBy + enrolledAt`. Tri inclut la fenêtre. `AgentPerformanceWidget` ajoute colonne « Filleuls » (fenêtre / total).
- **Fichiers touchés** : `supabase/functions/server/index.tsx` (signup, agent/clients, admin/members enroller, admin/agents/performance), `validators.ts` (SignupSchema), `src/app/espace-client/AuthContext.tsx`, `src/app/components/InscriptionPage.tsx`, `src/app/agent/api.ts` (createClient), `src/app/agent/pages/AgentPortfolioPage.tsx`, `src/app/espace-client/api.ts` (adminSetEnroller + AdminMember.enrolledBy + enrollments perf), `src/app/espace-client/pages/AdminPage.tsx` (EnrollerReassignButton, colonne Filleuls).

### 2.4.quaterdecies Suite enrôlement F14 a→c (✅ session du 2026-05-30)
- **F14a — MemberDrawer admin** : nouvelle section « Enrôlement » (matricule, date, source) + bouton `EnrollerReassignButton` réutilisé pour réattribuer depuis le drawer détail. `Profile` interface étendue (`enrolledBy/At/Source/byUid`, `referralCode`).
- **F14b — Console agent / filtre « Mes filleuls »** :
  - Backend `GET /agent/portfolio` fait désormais l'**union** des assignés (`conv:meta.assignee === mat`) et des **enrôlés** (`profile.enrolledBy === mat`) → un filleul apparaît même si sa conv n'est pas encore assignée. Chaque client expose `enrolledBy/At/Source` + booléen `assigned`.
  - `AgentPortfolioPage` : toggle pill « Tous (n) » / « Mes filleuls (n) ». Chip rouge « FILLEUL » sur les cartes où `enrolledBy === matricule`, chip gris « non assigné » sinon.
- **F14c — Export CSV filleuls par conseiller** :
  - `GET /admin/export/enrollments?matricule=...&since=YYYY-MM-DD` : 1 ligne par filleul (enrolledBy, enrolledAt, source, n° membre, nom, email, createdAt, contracts, payments_count, revenue_xof), summary header avec totaux. Audit `admin.export.enrollments`.
  - `api.adminDownloadEnrollmentsCsv()` côté front. `AgentPerformanceWidget` ajoute bouton global « Filleuls CSV » + lien `Download` cliquable sur chaque ligne (filleul d'un seul conseiller).

### 2.4.quindecies Batch F13 → F16 — health, sécurité plateforme, conformité, 2FA agent (✅ session du 2026-05-30)
- **F13 — `/health` enrichi + `/ping`** : flags d'intégrations (resend, termii, kkiapay, webauthn, agentSignup) + bloc `operations` (agents en ligne, dernier billing run). Endpoint `/ping` retournant `pong` pour les sondes externes.
- **F14 — Rotation HMAC admin** : `POST /admin/security/rotate-hmac` (superadmin) génère un nouveau secret 32 octets, invalide cache + tous les tokens admin et conseillers. Audit `admin.security.hmac.rotated` avec prefix-only logging. Tile « danger zone » dans `AdminPage`.
- **F15 — Bannière cookies (loi 2017-20 + RGPD)** : composant `<CookieConsent />` monté dans `Layout`. Choix « Tout accepter » / « Essentiels uniquement ». Émet un `CustomEvent("ippoo:consent")` pour brancher mesure d'audience conditionnelle. Helper `getCookieConsent()` exporté.
- **F16 — 2FA TOTP conseillers (RFC 6238)** :
  - Clé `agent:totp:<uid>` = `{ secret base32 20 octets, status: "pending"|"active", enabledAt }`.
  - Endpoints `GET /agent/2fa` (status), `POST /agent/2fa/enroll` (génère secret + URI otpauth), `POST /agent/2fa/activate` (vérifie premier code, renvoie token de session HMAC 8 h), `POST /agent/2fa/verify` (challenge), `POST /agent/2fa/disable` (exige un code TOTP courant).
  - `/agent/me` retourne `twoFactor: { enrolled, verified, required }`.
  - Helper serveur `requireAgent2FA(c, agentId)` câblé sur les endpoints sensibles : `POST /agent/payments/:uid`, `POST /agent/subscribe/:uid`, `POST /agent/claims/:userId/:claimId/status`, `POST /agent/kyc/:userId/:kycId/decision`. Refus 401 `twofactor-required` sans token de session valide.
  - Frontend : `apiFetch` injecte automatiquement `X-Agent-2FA-Token` (sessionStorage) sur tous les appels `/agent/*`. `AgentShell` gate l'arbre derrière `<Agent2FAChallenge />` quand `enrolled && !verified`. Section TOTP complète dans `AgentProfilePage` (QR code généré localement pour la sécurité, secret affiché en clair, premier code de confirmation, désactivation protégée). Token effacé sur tout signOut.
  - Env optionnel `AGENT_2FA_REQUIRED=1` exposé via `/agent/me` pour permettre, demain, de bloquer l'inscription d'un conseiller sans 2FA active.

### 2.4.sexdecies Batch F17 → F20 — espace client P0/P1 (✅ session du 2026-05-30)
- **F17 — Renouvellement tracker contrat** : après `POST /contracts/:id/renew`, le contrat se voit ajouter `pendingRenewalPaymentId` + `pendingRenewalAt`. Effets de paiement (`applyPaymentSideEffects` purpose `renewal`) nettoient ces champs. `ContratsPage` affiche un badge bleu « Renouvellement en attente — paiement en cours de validation » et masque le bandeau d'échéance pendant ce délai. Évite la double-action « Renouveler ».
- **F18 — Relance paiements en attente + suspension auto** : `runRemindersCycle` ajoute 3 paliers idempotents sur paiements `pending` (`pending3d:`, `pending5d:`, `suspend:`). À 7 jours, le contrat lié passe `status: "suspended"` avec `suspendedReason: "payment-overdue:<paymentId>"`, audit `contract.suspended.auto`. Réactivation automatique au prochain `monthly_premium` validé (`status: wasSuspended ? "active" : status`, `suspendedAt: null`).
- **F19 — KYC SLA + bouton « Relancer mon conseiller »** : nouveau `POST /kyc/remind` (rate-limit 1/24 h via `guardRate`) → met à jour `remindedAt` + `remindCount`, broadcast `kyc:remind` sur `agent:inbox`, audit `kyc.remind`. `KycPage` calcule l'âge de la demande pending (overdue ≥ 3 jours : palette rouge + chip durée), bouton de relance désactivé pendant 24 h post-relance avec dernière date affichée.
- **F20 — Sinistre lié bénéficiaire** : `ClaimCreateSchema` accepte `beneficiaryId`. `POST /claims` snapshot `{id, name, relation}` dans `claim.beneficiary` (snapshot car le bénéficiaire peut être renommé/supprimé ensuite). `SinistresPage` charge la liste des bénéficiaires et propose un `<select>` dans le formulaire (« Aucun (sinistre me concernant) » par défaut).
- **F27 — Audit exports comptables (SHA-256)** : helper `sha256Hex()` (WebCrypto). Les 3 endpoints `GET /admin/export/(accounting|commissions|enrollments)` calculent désormais le hash SHA-256 du corps généré, l'inscrivent dans l'audit utilisateur (`audit("admin:...")`) **et** dans la ring admin (`adminAudit`) avec `{filename, bytes, sha256, totaux}`. Le hash est aussi renvoyé via le header de réponse `X-Export-Sha256` (exposé via `Access-Control-Expose-Headers`) pour permettre une vérification d'intégrité côté admin (download + check). Trace anti-fraude / preuve d'export.
- **F26 — Widget alertes Overview admin** : `/admin/stats` retourne désormais un bloc `alerts: { paymentsStale2d, claimsStale48h, kycStale24h, agentsOffline4h }` calculé sur l'ensemble des KV (paiements `pending|failed|echec` > 2 j, sinistres `en_cours|soumis|en_examen` > 48 h, KYC `pending` > 24 h, présence conseiller non-`online` > 4 h). `OverviewTab` affiche en tête de page une bannière verte « tout est à jour » ou une carte « Alertes opérationnelles » avec 4 tuiles colorisées selon la gravité (rouge / orange / ambre / bleu).
- **F25 — Drawer historique inbox agent** : nouveau store module `inboxHistory.ts` (10 derniers événements `message:new` / `claim:new` / `kyc:new`). `AgentInboxNotifier` y pousse à chaque réception. Nouveau composant `AgentInboxHistoryBell` (icône Inbox + badge unread non-vus + drawer latéral droit qui liste les événements, navigation au clic, bouton « Effacer l'historique »). Monté dans le header `AgentShell` à côté de `AgentNotifBell`.
- **F24 — Souscription depuis fiche client agent** : déjà câblé (audit obsolète). Modal « Souscription assistée » dans `AgentCustomerPage` appelle `agentApi.subscribeForUser` → `POST /agent/subscribe/:uid` (tracé `subscribedBy` matricule + notif client + audit `agent.contract.subscribe`). Vérification effectuée.
- **F23 — Sinistres orphelins « Assigner à moi »** : nouveau `POST /agent/claims/:userId/:claimId/assign-me` (409 si déjà assigné à un autre conseiller, sinon set `assignedTo` + audit `claim.assign.self` + broadcast `claim:assign`). `AgentClaimsPage` détecte les sinistres orphelins (sans `assignedTo` et statut non terminal), affiche une bannière ambre récapitulative, tinte les cartes en ambre et expose un bouton inline « Assigner à moi » (sans ouvrir la sheet).
- **F22 — KYC FIFO + lock 15 min conseiller** : la file pending est déjà triée ASC par `createdAt` (FIFO). Nouvelle clé `kyc:lock:<uid>:<kycId>` = `{agentId, agentMatricule, agentName, lockedAt, expiresAt}`. Endpoint `POST /agent/kyc/:userId/:kycId/lock` (body `{force?, release?}`) : acquiert / renouvelle / libère un verrou 15 min, renvoie `409 verrou-occupe` si tenu par un autre conseiller (sans `force`). `GET /agent/kyc` enrichit chaque demande pending avec `lock.lockedByMe`. `POST /agent/kyc/:userId/:kycId/decision` refuse `409` si verrou ennemi actif, et purge le verrou après décision. `AgentKycPage` : chip de verrou dans la liste, bouton « Verrouiller / Libérer / Forcer » dans la sheet, boutons décision désactivés tant que le verrou est tenu par un autre. Confirme via `confirm()` avant un force.
- **F30 — Cron reminders auto-scheduler** : middleware global Hono (`app.use("*")`) qui déclenche `runRemindersCycle("auto")` au plus toutes les 15 min sans aucun scheduler externe. Verrou KV `reminders:auto:lock` (timestamp) + flag in-process `autoRemindersInflight` empêchent le double-fire en cas de bursts. Exécution détachée de la réponse via `EdgeRuntime.waitUntil` quand disponible (sinon fire-and-forget). Co-existe avec `POST /reminders/cron` (déclenchement externe `X-Cron-Secret`) et `POST /admin/reminders/run` (manuel super-admin) qui restent disponibles.
- **F29 — Toggle auto-débit admin** : nouveau `PATCH /admin/contracts/:userId/:id/auto-debit` (body `{enabled}`) — résout les demandes téléphoniques sans avoir à se connecter au compte client. Idempotent (`unchanged:true` si déjà dans l'état demandé), restaure `nextBillingDate` si réactivation, audit doublé (`audit("contract.autoDebit.adminToggle")` côté utilisateur + `adminAudit("admin.contract.autoDebit")` côté ring admin). `ContractsTab` expose un bouton chip vert « Auto-débit ON » / gris « Auto-débit OFF » par ligne, avec `confirm()` avant action et `dataQ.reload()` après succès.
- **F28 — Broadcast SMS visibilité livraison** : `POST /admin/broadcast` ventile désormais les stats en buckets distincts : `in_app|push|email|sms` (envois OK), `sms_failed|email_failed|push_failed` (échec d'envoi), `no_phone|no_email` (pas de destinataire), `opted_out` (désinscrit). `BroadcastTab` (toast + chips dans l'historique) affiche les buckets en couleurs : rouge pour les *_failed, gris pour no_*/opt-out. Le toast bascule en `warning` si des échecs sont remontés. `BroadcastStats` typé côté `api.ts`.
- **F21 — Attestation PDF + cache offline** : `downloadAttestation` déjà câblé dans `ContratsPage` et `AgentCustomerPage`. Service Worker enrichi d'une route `NetworkFirst` (timeout 4 s, TTL 7 jours, 80 entrées) sur les GET `contracts|payments|profile|notifications` du serveur Edge. Cache **partitionné par token Bearer** (`cacheKeyWillBeUsed` injecte les 16 derniers caractères de l'Authorization dans la clé) pour éviter toute fuite entre utilisateurs sur un device partagé. `AuthContext.signOut()` envoie un message `IPPOO_CLEAR_OFFLINE_CACHE` au SW qui purge le cache. Permet aux clients de consulter et télécharger leur attestation hors-ligne.

### 2.6 Sécurité & isolation
- Auth admin **strictement séparée** de Supabase Auth : `ADMIN_USERNAME` / `ADMIN_PASSWORD` (ou `ADMIN_ACCOUNTS` JSON multi-comptes) + jeton HMAC signé, TTL 8 h, header `X-Admin-Token`.
- 2FA TOTP supportée (`ADMIN_TOTP_SECRET`) — challenge intermédiaire `POST /admin/login` puis `POST /admin/login/2fa`.
- `SUPABASE_SERVICE_ROLE_KEY` ne fuit jamais côté client.
- Rate-limiting in-memory KV pour signup, suppression compte, etc.
- WebAuthn (passkeys) câblé pour login client (`/auth/webauthn/*`).

---

## 3. Intégrations opérationnelles

| Domaine        | État        | Détails / clé requise                                                |
| -------------- | ----------- | -------------------------------------------------------------------- |
| Auth client    | ✅ OK       | Supabase Auth (email/password, magic link via QR, WebAuthn passkeys) |
| Auth admin     | ✅ OK       | `ADMIN_USERNAME` + `ADMIN_PASSWORD` (+ `ADMIN_TOTP_SECRET` optionnel)|
| KV store       | ✅ OK       | Table `kv_store_752d1a39` (unique, **ne pas créer d'autres tables**) |
| Storage        | ✅ OK       | Buckets `make-752d1a39-claims` + `make-752d1a39-messages` + `make-752d1a39-kyc` + `make-752d1a39-avatars` privés |
| Realtime       | ✅ OK       | Broadcast REST `/realtime/v1/api/broadcast` côté serveur             |
| Paiement       | ⚠️ Sandbox   | **KKiaPay** : `KKIAPAY_PUBLIC_KEY`, `KKIAPAY_PRIVATE_KEY`, `KKIAPAY_SECRET`, `KKIAPAY_SANDBOX` (passer à `false` en prod). Webhook : `/payments/kkiapay/webhook`. |
| Email          | ⚠️ Optionnel| **Resend** : `RESEND_API_KEY`, `RESEND_FROM` (sinon factures + broadcasts email skip). |
| SMS            | ⚠️ Optionnel| **Termii** : `TERMII_API_KEY`, `TERMII_SENDER_ID` (sinon broadcasts SMS skip). |
| Web Push VAPID | ❌ À configurer | `VAPID_PUBLIC`, `VAPID_PRIVATE`, `VAPID_SUBJECT` (mailto:). Sans, push fallback in-app + realtime only. |
| Apple Wallet   | ❌ Non câblé| Route `/wallet/apple` renvoie 503. Nécessite Pass Type ID Apple Developer. |
| Google Wallet  | ⚠️ Conditionnel | Variables `GOOGLE_WALLET_ISSUER_ID`, `GOOGLE_WALLET_CLASS_ID`, `GOOGLE_WALLET_SERVICE_ACCOUNT_JSON`. |

---

### Variables nouvelles
- `AGENT_EMAILS` (optionnel) — liste d'emails séparés par virgules autorisés à utiliser `/agent/*` sans avoir `user_metadata.role === "agent"`. Utile pour amorcer l'équipe avant qu'un outil admin n'existe.
- `AGENT_SIGNUP_CODE` (recommandé) — code d'invitation partagé exigé par `POST /agent/signup` (page `/agent/inscription`). Sans cette variable, l'inscription conseiller est désactivée (503).
- `COMMISSION_RATE_AGENT` (optionnel, défaut `0.05`) — taux appliqué aux paiements `collectedBy` lors des exports comptables et commissions agent. Valeurs `0..1`.

## 4. Variables d'environnement (Supabase Edge Functions)

### Déjà fournies par l'utilisateur
- `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_PUBLISHABLE_KEYS`, `SUPABASE_SECRET_KEYS`, `SUPABASE_DB_URL`, `SUPABASE_JWKS`
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`

### À configurer pour passage en prod
```
# Paiement (obligatoire en prod)
KKIAPAY_PUBLIC_KEY=
KKIAPAY_PRIVATE_KEY=
KKIAPAY_SECRET=
KKIAPAY_SANDBOX=false

# Notifications transactionnelles (recommandé)
RESEND_API_KEY=
RESEND_FROM=IPPOO Assurance <no-reply@ippoo.bj>
TERMII_API_KEY=
TERMII_SENDER_ID=IPPOO

# Web Push natif (recommandé pour PWA)
VAPID_PUBLIC=
VAPID_PRIVATE=
VAPID_SUBJECT=mailto:contact@ippoo.bj

# Sécurité admin (recommandé)
ADMIN_TOTP_SECRET=             # Active 2FA TOTP
ADMIN_ACCOUNTS=[{"username":"…","password":"…","role":"superadmin","totpSecret":"…"}]

# Wallet (optionnel)
GOOGLE_WALLET_ISSUER_ID=
GOOGLE_WALLET_CLASS_ID=
GOOGLE_WALLET_SERVICE_ACCOUNT_JSON=
```

---

## 5. Checklist avant mise en production

### Backend
- [ ] Configurer **toutes** les variables KKiaPay et désactiver `KKIAPAY_SANDBOX`.
- [ ] Déclarer le webhook KKiaPay (`/functions/v1/make-server-752d1a39/payments/kkiapay/webhook`) côté tableau de bord KKiaPay.
- [ ] Configurer Resend (domaine vérifié, SPF/DKIM/DMARC) pour les factures + broadcasts.
- [ ] Configurer Termii avec un sender ID approuvé pour le Bénin.
- [ ] Générer une paire VAPID (`npx web-push generate-vapid-keys`) et déployer les 3 variables.
- [ ] Définir `ADMIN_ACCOUNTS` multi-utilisateurs avec TOTP au lieu de l'unique compte legacy.
- [ ] Vérifier que `SUPABASE_SERVICE_ROLE_KEY` n'est utilisée que côté Edge Function.
- [ ] Mettre en place une rotation périodique du secret HMAC (`system:hmac:secret` dans KV).

### Frontend
- [x] Service worker n'intercepte pas les appels `/functions/v1/`.
- [ ] Forcer la mise à jour du SW pour les utilisateurs existants (déjà géré via `cleanupOutdatedCaches`).
- [ ] Vérifier que `import.meta.env` ne contient que des clés publiques (`projectId`, `publicAnonKey`).
- [ ] Tester le tunnel paiement end-to-end avec un vrai compte KKiaPay sandbox puis prod.
- [ ] Confirmer que `Notification.requestPermission()` est appelé au bon moment (UX) — actuellement déclenché par l'opt-in push dans Paramètres.

### Conformité & légal
- [ ] Mentions légales, CGU, politique de confidentialité (RGPD + loi béninoise n° 2017-20 sur la protection des données).
- [ ] Bandeau cookie/consentement si analytics tiers ajoutés.
- [ ] Procédure de suppression de compte (déjà câblée : `/account/delete` avec délai 30 j + `/account/delete-now`).
- [ ] Export des données utilisateur (`/account/export`) — vérifier complétude (profil, contrats, sinistres, paiements, bénéficiaires, notifications, audit).

### Observabilité
- [ ] Brancher un collecteur de logs (Logflare ou équivalent) sur l'Edge Function.
- [ ] Mettre en place un monitoring uptime sur `/health` (à créer si absent).
- [ ] Alerting sur taux d'erreur paiement + 401 anormaux.

### Performance
- [ ] Mesurer Time-To-Interactive sur connexion 3G (cible : < 4 s grâce au PWA + service worker).
- [ ] Vérifier la taille du bundle et le code-splitting des grosses pages (admin, souscription).
- [ ] Activer la compression Brotli côté Supabase (par défaut OK).

---

## 6. Points d'attention / dette technique

- **Une seule table KV** : tout le modèle de données est stocké dans `kv_store_752d1a39` (préfixes `profile:`, `contracts:`, `notifications:`, etc.). Pas de DDL possible dans Make. Pour un volume > 100k users, prévoir migration Postgres dédiée hors Make.
- **Broadcasts non-persistants** : les events Realtime sont éphémères. Un user offline ne « rejoue » pas l'event — il récupère via le polling/refetch React Query. C'est le comportement souhaité.
- **`notify()` plafonne à 50 entrées** dans certains call-sites et 100/200 dans d'autres. À harmoniser si rétention longue requise.
- **WhatsApp Click-to-Chat** : le numéro `22901415210092` est codé en dur dans `WhatsAppButton.tsx`. Centraliser dans `SiteContent` si plusieurs canaux.
- **Images Unsplash** : actuellement chargées depuis le CDN public. Pour la prod, envisager d'héberger une copie optimisée (Supabase Storage public bucket + transform) pour la performance + l'indépendance.

---

## 7. Ressources & fichiers clés

| Fichier                                                  | Rôle                                              |
| -------------------------------------------------------- | ------------------------------------------------- |
| `supabase/functions/server/index.tsx`                    | Edge Function unique (Hono) — tout le backend     |
| `supabase/functions/server/kv_store.tsx`                 | Helpers KV (**ne jamais modifier**)               |
| `supabase/functions/server/validators.ts`                | Schémas zod pour parseBody                        |
| `src/app/espace-client/EspaceLayout.tsx`                 | Shell appli client (auth, toast, realtime)        |
| `src/app/espace-client/NotificationsRealtime.tsx`        | Listener push-style global                        |
| `src/app/espace-client/api.ts`                           | Client API typé                                   |
| `src/app/espace-client/pages/AdminPage.tsx`              | Back-office (tabs Members, Messages, Stats…)     |
| `src/app/data/productCatalog.ts`                         | Catalogue 11 offres (synchro avec site public)    |
| `src/sw.ts`                                              | Service Worker Workbox                            |
| `src/app/espace-client/push.ts`                          | Web Push VAPID (subscribe/unsubscribe)            |
