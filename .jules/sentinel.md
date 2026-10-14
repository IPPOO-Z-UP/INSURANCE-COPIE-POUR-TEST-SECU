## 2026-05-25 - Safe PostgREST Array Filtering in KV Store

**Vulnerability:**
Manual string interpolation inside PostgREST filter `delQuery.not("id", "in", \`(\${newIds.map(id => \`"\${id}"\`).join(",")})\`)` allowed potential filter syntax injection if array elements contained special characters like double quotes or parentheses.

**Learning:**
Constructing PostgREST filter strings via JavaScript string templates bypasses the SDK's internal parameter escaping and sanitization.

**Prevention:**
Always pass array values directly into PostgREST filter functions (e.g. `.not("id", "in", newIds)`) rather than building raw SQL/PostgREST filter strings manually.
