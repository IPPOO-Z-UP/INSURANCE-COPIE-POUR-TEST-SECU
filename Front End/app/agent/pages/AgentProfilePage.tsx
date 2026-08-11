import { useEffect, useState } from "react";
import { Save, KeyRound, Eye, EyeOff, RefreshCw, LogOut, ShieldCheck, ShieldOff, Bell, BellOff } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { pushStatus, isSubscribed, subscribeToPush, unsubscribeFromPush } from "../../espace-client/push";
import { useNavigate } from "react-router";
import { useAuth } from "../../espace-client/AuthContext";
import { agentApi, setStoredAgent2FAToken } from "../api";
import { apiFetch } from "../../espace-client/supabaseClient";

export function AgentProfilePage() {
  const { session, signOut, user } = useAuth();
  const token = session?.access_token ?? "";
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [phone, setPhone] = useState("");
  const [avatarUrl, setAvatarUrl] = useState("");
  const [signature, setSignature] = useState("");

  // Password change
  const [pwd, setPwd] = useState("");
  const [pwd2, setPwd2] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [pwdBusy, setPwdBusy] = useState(false);
  const [pwdMsg, setPwdMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function reload() {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await agentApi.getProfile(token);
      setDisplayName(res.profile.displayName ?? "");
      setPhone(res.profile.phone ?? "");
      setAvatarUrl(res.profile.avatarUrl ?? "");
      setSignature(res.profile.signature ?? "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erreur de chargement");
    } finally { setLoading(false); }
  }
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [token]);

  async function save() {
    if (!token) return;
    setBusy(true); setOk(null); setError(null);
    try {
      await agentApi.updateProfile(token, { displayName, phone, avatarUrl, signature });
      setOk("Profil mis à jour");
      setTimeout(() => setOk(null), 2500);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erreur de sauvegarde");
    } finally { setBusy(false); }
  }

  async function changePassword() {
    setPwdMsg(null);
    if (pwd.length < 8) { setPwdMsg({ kind: "err", text: "Au moins 8 caractères." }); return; }
    if (pwd !== pwd2) { setPwdMsg({ kind: "err", text: "Les deux mots de passe ne correspondent pas." }); return; }
    setPwdBusy(true);
    try {
      await apiFetch<{ ok: true }>("/change-password", { method: "POST", token, body: { newPassword: pwd } });
      setPwd(""); setPwd2("");
      setPwdMsg({ kind: "ok", text: "Mot de passe changé." });
    } catch (err) {
      setPwdMsg({ kind: "err", text: err instanceof Error ? err.message : "Erreur" });
    } finally { setPwdBusy(false); }
  }

  return (
    <div className="px-4 py-4">
      <header className="mb-3 flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="truncate" style={{ fontSize: "1.4rem", fontWeight: 900, letterSpacing: "-0.025em" }}>
            Mon profil
          </h1>
          <p className="truncate" style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--ippoo-text-muted)" }}>
            {user?.email}
          </p>
        </div>
        <button
          onClick={reload}
          className="min-w-[44px] min-h-[44px] rounded-full flex items-center justify-center active:scale-95 transition"
          style={{ border: "1px solid var(--line-hairline)", background: "var(--surface-card)" }}
          aria-label="Recharger"
        >
          <RefreshCw className={`w-[18px] h-[18px] ${loading ? "animate-spin" : ""}`} />
        </button>
      </header>

      {error && (
        <div className="px-4 py-3 rounded-xl bg-red-50 border border-red-200 text-red-700 mb-3" style={{ fontSize: "0.85rem" }}>
          {error}
        </div>
      )}
      {ok && (
        <div className="px-4 py-3 rounded-xl mb-3" style={{ background: "rgba(22,178,106,0.12)", color: "#0F7A47", fontSize: "0.85rem", fontWeight: 700 }}>
          {ok}
        </div>
      )}

      <section
        className="rounded-3xl p-4 mb-3"
        style={{ background: "var(--surface-card)", border: "1px solid var(--line-hairline)" }}
      >
        <p style={{ fontSize: "0.92rem", fontWeight: 800 }}>Identité affichée</p>
        <p className="mb-3" style={{ fontSize: "0.78rem", color: "var(--ippoo-text-muted)" }}>
          Ces informations apparaissent dans la messagerie côté client.
        </p>

        <label className="block mb-1" style={{ fontSize: "0.78rem", fontWeight: 700 }}>Nom affiché</label>
        <input
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="Prénom Nom"
          className="w-full mb-2 px-3 py-2 rounded-xl"
          style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "16px" }}
        />

        <label className="block mb-1" style={{ fontSize: "0.78rem", fontWeight: 700 }}>Téléphone direct</label>
        <input
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          placeholder="+229 01 …"
          className="w-full mb-2 px-3 py-2 rounded-xl"
          style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "16px" }}
        />

        <label className="block mb-1" style={{ fontSize: "0.78rem", fontWeight: 700 }}>Photo (URL)</label>
        <input
          value={avatarUrl}
          onChange={(e) => setAvatarUrl(e.target.value)}
          placeholder="https://…"
          className="w-full mb-2 px-3 py-2 rounded-xl"
          style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "16px" }}
        />

        <label className="block mb-1" style={{ fontSize: "0.78rem", fontWeight: 700 }}>Signature (mail / SMS)</label>
        <textarea
          value={signature}
          onChange={(e) => setSignature(e.target.value)}
          rows={3}
          placeholder={"Cordialement,\nPrénom Nom – Conseiller IPPOO"}
          className="w-full mb-3 px-3 py-2 rounded-xl"
          style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "15px" }}
        />

        <button
          onClick={save}
          disabled={busy}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl disabled:opacity-50"
          style={{ background: "var(--ippoo-text)", color: "var(--surface-card)", fontSize: "0.85rem", fontWeight: 800 }}
        >
          <Save className="w-4 h-4" /> {busy ? "…" : "Enregistrer"}
        </button>
      </section>

      <section
        className="rounded-3xl p-4 mb-3"
        style={{ background: "var(--surface-card)", border: "1px solid var(--line-hairline)" }}
      >
        <p style={{ fontSize: "0.92rem", fontWeight: 800 }}>Sécurité</p>
        <p className="mb-3" style={{ fontSize: "0.78rem", color: "var(--ippoo-text-muted)" }}>
          Changer votre mot de passe de connexion.
        </p>
        <div className="relative mb-2">
          <KeyRound className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "var(--ippoo-text-muted)" }} />
          <input
            type={showPwd ? "text" : "password"}
            value={pwd}
            onChange={(e) => setPwd(e.target.value)}
            placeholder="Nouveau mot de passe"
            className="w-full pl-10 pr-10 py-2 rounded-xl"
            style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "16px" }}
          />
          <button
            type="button"
            onClick={() => setShowPwd((v) => !v)}
            className="absolute right-2 top-1/2 -translate-y-1/2 p-1"
            aria-label={showPwd ? "Masquer" : "Afficher"}
          >
            {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        <input
          type={showPwd ? "text" : "password"}
          value={pwd2}
          onChange={(e) => setPwd2(e.target.value)}
          placeholder="Confirmer le mot de passe"
          className="w-full mb-2 px-3 py-2 rounded-xl"
          style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "16px" }}
        />
        {pwdMsg && (
          <p className="mb-2" style={{ fontSize: "0.8rem", color: pwdMsg.kind === "ok" ? "#0F7A47" : "#B42318", fontWeight: 700 }}>
            {pwdMsg.text}
          </p>
        )}
        <button
          onClick={changePassword}
          disabled={pwdBusy || !pwd || !pwd2}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl disabled:opacity-50"
          style={{ background: "var(--accent-primary)", color: "white", fontSize: "0.85rem", fontWeight: 800 }}
        >
          <KeyRound className="w-4 h-4" /> {pwdBusy ? "…" : "Changer le mot de passe"}
        </button>
      </section>

      <TwoFactorSection token={token} />

      <PushSection token={token} />

      <button
        onClick={async () => { setStoredAgent2FAToken(null); await signOut(); navigate("/agent/connexion"); }}
        className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-2xl"
        style={{ background: "var(--surface-card)", border: "1px solid var(--line-hairline)", color: "#B42318", fontSize: "0.88rem", fontWeight: 800 }}
      >
        <LogOut className="w-4 h-4" /> Se déconnecter
      </button>
    </div>
  );
}

// A2 — Section notifications push agent. Réutilise les helpers push.ts du
// client (génériques : Bearer token utilisateur, KV `push:subs:<uid>`).
// Permet aux conseillers de recevoir une notif système hors-onglet quand un
// ticket leur est assigné, qu'un client envoie un message, ou qu'un admin
// prend une décision sur leur dossier.
function PushSection({ token }: { token: string }) {
  const [perm, setPerm] = useState<"unsupported" | "denied" | "granted" | "default" | "loading">("loading");
  const [subscribed, setSubscribed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function refresh() {
    setPerm(await pushStatus());
    setSubscribed(await isSubscribed());
  }
  useEffect(() => { refresh(); }, []);

  async function activate() {
    setBusy(true); setMsg(null);
    try {
      await subscribeToPush(token);
      setMsg({ kind: "ok", text: "Notifications activées sur cet appareil." });
      await refresh();
    } catch (err) {
      setMsg({ kind: "err", text: err instanceof Error ? err.message : "Erreur" });
    } finally { setBusy(false); }
  }
  async function disable() {
    setBusy(true); setMsg(null);
    try {
      await unsubscribeFromPush(token);
      setMsg({ kind: "ok", text: "Notifications désactivées sur cet appareil." });
      await refresh();
    } catch (err) {
      setMsg({ kind: "err", text: err instanceof Error ? err.message : "Erreur" });
    } finally { setBusy(false); }
  }

  return (
    <section className="rounded-3xl p-4 mb-3" style={{ background: "var(--surface-card)", border: "1px solid var(--line-hairline)" }}>
      <div className="flex items-center gap-2 mb-1">
        {subscribed ? <Bell className="w-4 h-4" style={{ color: "#0F7A47" }} /> : <BellOff className="w-4 h-4" style={{ color: "var(--ippoo-text-muted)" }} />}
        <p style={{ fontSize: "0.92rem", fontWeight: 800 }}>Notifications push</p>
      </div>
      <p className="mb-3" style={{ fontSize: "0.78rem", color: "var(--ippoo-text-muted)" }}>
        Recevez une alerte système même quand la console est fermée : nouveau ticket assigné, message client, décision admin sur vos dossiers.
      </p>
      {perm === "unsupported" && (
        <p style={{ fontSize: "0.8rem", color: "#B42318", fontWeight: 700 }}>Cet appareil ne supporte pas les notifications push.</p>
      )}
      {perm === "denied" && (
        <p style={{ fontSize: "0.8rem", color: "#B42318", fontWeight: 700 }}>Permission refusée. Réactivez-les dans les réglages du navigateur.</p>
      )}
      {(perm === "default" || perm === "granted") && (
        subscribed ? (
          <button onClick={disable} disabled={busy} className="inline-flex items-center gap-2 px-4 py-2 rounded-xl disabled:opacity-50"
            style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", color: "#B42318", fontSize: "0.85rem", fontWeight: 800 }}>
            <BellOff className="w-4 h-4" /> {busy ? "…" : "Désactiver sur cet appareil"}
          </button>
        ) : (
          <button onClick={activate} disabled={busy} className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-white disabled:opacity-50"
            style={{ background: "var(--accent-primary)", fontSize: "0.85rem", fontWeight: 800 }}>
            <Bell className="w-4 h-4" /> {busy ? "…" : "Activer les notifications"}
          </button>
        )
      )}
      {msg && (
        <p className="mt-2" style={{ fontSize: "0.8rem", color: msg.kind === "ok" ? "#0F7A47" : "#B42318", fontWeight: 700 }}>{msg.text}</p>
      )}
    </section>
  );
}

// Section 2FA TOTP. Trois états possibles :
//  - non inscrit : bouton "Activer" → POST /enroll → on affiche secret + QR
//    + saisie d'un premier code pour confirmer l'enrôlement.
//  - inscrit (pending) : même UI que l'étape de confirmation ci-dessus.
//  - actif : tile "Activé le …" + bouton "Désactiver" (exige un code TOTP).
function TwoFactorSection({ token }: { token: string }) {
  const [status, setStatus] = useState<{ enrolled: boolean; pending: boolean; enabledAt: string | null } | null>(null);
  const [loading, setLoading] = useState(true);
  const [enrollData, setEnrollData] = useState<{ secret: string; otpauth: string } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [disableMode, setDisableMode] = useState(false);

  async function reload() {
    if (!token) return;
    setLoading(true);
    try { setStatus(await agentApi.twoFactor.status(token)); }
    catch (err) { setMsg({ kind: "err", text: err instanceof Error ? err.message : "Erreur" }); }
    finally { setLoading(false); }
  }
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [token]);

  async function startEnroll() {
    setBusy(true); setMsg(null);
    try {
      setEnrollData(await agentApi.twoFactor.enroll(token));
      setCode("");
    } catch (err) {
      setMsg({ kind: "err", text: err instanceof Error ? err.message : "Erreur" });
    } finally { setBusy(false); }
  }

  async function activate() {
    if (code.length !== 6) { setMsg({ kind: "err", text: "Code à 6 chiffres requis." }); return; }
    setBusy(true); setMsg(null);
    try {
      const { twoFactorToken } = await agentApi.twoFactor.activate(token, code);
      setStoredAgent2FAToken(twoFactorToken);
      setEnrollData(null);
      setCode("");
      setMsg({ kind: "ok", text: "2FA activée. Conservez votre secret de secours dans un coffre-fort." });
      await reload();
    } catch (err) {
      setMsg({ kind: "err", text: err instanceof Error ? err.message : "Code invalide." });
    } finally { setBusy(false); }
  }

  async function disable() {
    if (code.length !== 6) { setMsg({ kind: "err", text: "Code à 6 chiffres requis pour confirmer." }); return; }
    setBusy(true); setMsg(null);
    try {
      await agentApi.twoFactor.disable(token, code);
      setStoredAgent2FAToken(null);
      setDisableMode(false);
      setCode("");
      setMsg({ kind: "ok", text: "2FA désactivée." });
      await reload();
    } catch (err) {
      setMsg({ kind: "err", text: err instanceof Error ? err.message : "Code invalide." });
    } finally { setBusy(false); }
  }

  return (
    <section
      className="rounded-3xl p-4 mb-3"
      style={{ background: "var(--surface-card)", border: "1px solid var(--line-hairline)" }}
    >
      <div className="flex items-center gap-2 mb-1">
        {status?.enrolled ? <ShieldCheck className="w-4 h-4" style={{ color: "#0F7A47" }} /> : <ShieldOff className="w-4 h-4" style={{ color: "var(--ippoo-text-muted)" }} />}
        <p style={{ fontSize: "0.92rem", fontWeight: 800 }}>Authentification à deux facteurs (TOTP)</p>
      </div>
      <p className="mb-3" style={{ fontSize: "0.78rem", color: "var(--ippoo-text-muted)" }}>
        Obligatoire pour décider d'un sinistre, valider une KYC ou enregistrer un paiement. Utilisez Google Authenticator, Authy, 1Password, etc.
      </p>

      {loading && <p style={{ fontSize: "0.8rem" }}>Chargement…</p>}

      {!loading && !status?.enrolled && !enrollData && (
        <button
          onClick={startEnroll}
          disabled={busy}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-white disabled:opacity-50"
          style={{ background: "var(--accent-primary)", fontSize: "0.85rem", fontWeight: 800 }}
        >
          <ShieldCheck className="w-4 h-4" /> {busy ? "…" : "Activer la 2FA"}
        </button>
      )}

      {enrollData && (
        <div>
          <div className="flex flex-col sm:flex-row gap-4 items-center">
            {enrollData.otpauth && (
              <div className="p-2 bg-white rounded-xl border flex items-center justify-center" style={{ borderColor: "var(--line-hairline)", width: 180, height: 180 }}>
                <QRCodeSVG value={enrollData.otpauth} size={164} level="M" />
              </div>
            )}
            <div className="flex-1 min-w-0">
              <p style={{ fontSize: "0.78rem", color: "var(--ippoo-text-muted)" }}>
                Scannez le QR code, ou saisissez ce secret manuellement :
              </p>
              <code
                className="block mt-1 p-2 rounded-lg break-all"
                style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "0.85rem", letterSpacing: "0.1em" }}
              >
                {enrollData.secret}
              </code>
            </div>
          </div>
          <input
            inputMode="numeric"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            placeholder="Code à 6 chiffres"
            className="mt-3 w-full px-3 py-2 rounded-xl text-center tracking-[0.3em]"
            style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "1.1rem", fontWeight: 700 }}
          />
          <div className="flex gap-2 mt-2">
            <button
              onClick={activate}
              disabled={busy || code.length !== 6}
              className="flex-1 px-4 py-2 rounded-xl text-white disabled:opacity-50"
              style={{ background: "var(--accent-primary)", fontSize: "0.85rem", fontWeight: 800 }}
            >
              {busy ? "…" : "Confirmer et activer"}
            </button>
            <button
              onClick={() => { setEnrollData(null); setCode(""); }}
              className="px-4 py-2 rounded-xl"
              style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "0.85rem", fontWeight: 700 }}
            >
              Annuler
            </button>
          </div>
        </div>
      )}

      {!loading && status?.enrolled && !disableMode && (
        <div>
          <p style={{ fontSize: "0.82rem" }}>
            <span style={{ color: "#0F7A47", fontWeight: 800 }}>Activée</span>
            {status.enabledAt && <span style={{ color: "var(--ippoo-text-muted)" }}> — le {new Date(status.enabledAt).toLocaleDateString("fr-FR")}</span>}
          </p>
          <button
            onClick={() => { setDisableMode(true); setCode(""); setMsg(null); }}
            className="mt-2 inline-flex items-center gap-2 px-4 py-2 rounded-xl"
            style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", color: "#B42318", fontSize: "0.8rem", fontWeight: 800 }}
          >
            <ShieldOff className="w-4 h-4" /> Désactiver
          </button>
        </div>
      )}

      {status?.enrolled && disableMode && (
        <div>
          <p style={{ fontSize: "0.8rem", color: "var(--ippoo-text-muted)" }}>
            Saisissez un code TOTP courant pour confirmer la désactivation.
          </p>
          <input
            inputMode="numeric"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            placeholder="Code à 6 chiffres"
            className="mt-2 w-full px-3 py-2 rounded-xl text-center tracking-[0.3em]"
            style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "1.1rem", fontWeight: 700 }}
          />
          <div className="flex gap-2 mt-2">
            <button
              onClick={disable}
              disabled={busy || code.length !== 6}
              className="flex-1 px-4 py-2 rounded-xl text-white disabled:opacity-50"
              style={{ background: "#B42318", fontSize: "0.85rem", fontWeight: 800 }}
            >
              {busy ? "…" : "Désactiver la 2FA"}
            </button>
            <button
              onClick={() => { setDisableMode(false); setCode(""); }}
              className="px-4 py-2 rounded-xl"
              style={{ background: "var(--surface-app)", border: "1px solid var(--line-hairline)", fontSize: "0.85rem", fontWeight: 700 }}
            >
              Annuler
            </button>
          </div>
        </div>
      )}

      {msg && (
        <p className="mt-2" style={{ fontSize: "0.8rem", color: msg.kind === "ok" ? "#0F7A47" : "#B42318", fontWeight: 700 }}>
          {msg.text}
        </p>
      )}
    </section>
  );
}
