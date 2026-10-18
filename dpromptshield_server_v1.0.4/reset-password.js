// Emergency password reset for a console account (e.g. the superadmin forgot
// theirs). Run on the server machine — it talks to the database directly, so
// it needs the same .env as server.js.
//
//   node reset-password.js <username> <newPassword>
//
// Then RESTART the relay: login sessions live in server memory, so restarting
// also signs out anyone who was logged in as that account.
require("dotenv").config();
const sql = require("mssql");
const { hashPassword, checkPasswordPolicy } = require("./auth");

const [, , username, newPassword] = process.argv;
if (!username || !newPassword) {
  console.error("Usage: node reset-password.js <username> <newPassword>");
  process.exit(1);
}
const policyErr = checkPasswordPolicy(newPassword, username);
if (policyErr) { console.error(policyErr); process.exit(1); }

(async () => {
  const pool = await sql.connect({
    server: process.env.DB_SERVER,
    port: Number(process.env.DB_PORT || 1433),
    database: process.env.DB_DATABASE,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    options: {
      encrypt: process.env.DB_ENCRYPT !== "false",
      trustServerCertificate: process.env.DB_TRUST_SERVER_CERT !== "false",
    },
  });
  const r = pool.request();
  r.input("u", sql.NVarChar(50), username);
  r.input("h", sql.NVarChar(300), await hashPassword(newPassword));
  const res = await r.query(`
    UPDATE dbo.DPromptShieldAdmin
    SET PasswordHash = @h, PasswordChangedAt = SYSUTCDATETIME()
    WHERE LOWER(Username) = LOWER(@u)`);
  if (!res.rowsAffected[0]) {
    console.error(`No account named "${username}" found.`);
    process.exit(1);
  }
  console.log(`Password for "${username}" updated. Restart the relay to end any active sessions.`);
  await pool.close();
})().catch((e) => { console.error("reset failed:", e.message); process.exit(1); });
