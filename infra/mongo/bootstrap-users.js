// The protected VM Run Command runs mongosh on loopback and supplies the URI
// through its environment. No credential is a Terraform or command-line input.
const fs = require("fs");
const crypto = require("crypto");
const match = /^mongodb:\/\/tasky:([a-fA-F0-9]+)@mongo\.wiz\.internal:27017\/\?authSource=admin$/.exec(process.env.MONGODB_URI || "");
if (!match) throw new Error("Protected input does not match the Tasky connection contract");
const admin = db.getSiblingDB("admin");
function authenticated(result) {
  return result === 1 || result?.ok === 1;
}
function guestPassword(name) {
  const path = "/etc/outpost/" + name;
  try {
    fs.writeFileSync(path, crypto.randomBytes(32).toString("hex"), { mode: 0o600, flag: "wx" });
  } catch (err) {
    if (err.code !== "EEXIST") throw err;
  }
  const password = fs.readFileSync(path, "utf8");
  if (!/^[a-f0-9]{64}$/.test(password)) throw new Error("Invalid protected guest credential file");
  return password;
}
const adminPassword = guestPassword("admin-password");
let signedIn = false;
try {
  signedIn = authenticated(admin.auth("outpost-admin", adminPassword));
} catch (err) {
  if (err.code !== 18) throw err;
}
if (!signedIn) {
  admin.createUser({ user: "outpost-admin", pwd: adminPassword, roles: ["userAdminAnyDatabase"] });
  if (!authenticated(admin.auth("outpost-admin", adminPassword))) throw new Error("Admin authentication failed");
}
const backupPassword = guestPassword("backup-password");
for (const [user, pwd, role] of [["tasky", match[1], "readWrite"], ["outpost-backup", backupPassword, "read"]]) {
  const options = { pwd, roles: [{ role, db: "go-mongodb" }] };
  if (admin.getUser(user)) admin.updateUser(user, options);
  else admin.createUser({ user, ...options });
  const session = new Mongo("mongodb://127.0.0.1:27017").getDB("admin");
  if (!authenticated(session.auth(user, pwd))) throw new Error("Guest user authentication failed");
}
fs.writeFileSync("/etc/outpost/backup.json.tmp", JSON.stringify({
  uri: "mongodb://outpost-backup:" + backupPassword + "@127.0.0.1:27017/?authSource=admin"
}), { mode: 0o600 });
fs.renameSync("/etc/outpost/backup.json.tmp", "/etc/outpost/backup.json");
