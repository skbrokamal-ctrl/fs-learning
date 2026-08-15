const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

for (const d of ["data", "public/uploads/videos", "public/uploads/resources"]) {
  fs.mkdirSync(path.join(ROOT, d), { recursive: true });
}

const db = new Database(path.join(ROOT, "data/fs_learning.db"));
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  video_file TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS resources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lesson_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  file_name TEXT NOT NULL,
  original_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(lesson_id) REFERENCES lessons(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS enrollments (
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, course_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  admin_reply TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

const adminExists = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
if (!adminExists) {
  const hash = bcrypt.hashSync("admin12345", 10);
  db.prepare("INSERT INTO users (username,password_hash,name,role) VALUES (?,?,?,?)")
    .run("admin", hash, "FS Learning Admin", "admin");
}

const courseExists = db.prepare("SELECT id FROM courses LIMIT 1").get();
if (!courseExists) {
  const c = db.prepare("INSERT INTO courses (title,description) VALUES (?,?)")
    .run("CapCut Editing Course", "Demo course — replace this with your real course.");
  db.prepare("INSERT INTO lessons (course_id,title,description) VALUES (?,?,?)")
    .run(c.lastInsertRowid, "Day 3 — Ratio & Canvas", "Upload the real lesson video from the Admin Panel.");
}

app.set("view engine", "ejs");
app.set("views", path.join(ROOT, "views"));
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.json({ limit: "2mb" }));
app.use(session({
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET_BEFORE_DEPLOYING",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 1000*60*60*12 }
}));
app.use("/static", express.static(path.join(ROOT, "public")));

const videoStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, path.join(ROOT, "public/uploads/videos")),
  filename: (_, file, cb) => cb(null, Date.now() + "-" + safeName(file.originalname))
});
const resourceStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, path.join(ROOT, "public/uploads/resources")),
  filename: (_, file, cb) => cb(null, Date.now() + "-" + safeName(file.originalname))
});
const uploadVideo = multer({
  storage: videoStorage,
  limits: { fileSize: 1024 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, /^video\//.test(file.mimetype))
});
const uploadResource = multer({
  storage: resourceStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, file.mimetype === "application/pdf")
});

function safeName(name) {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_");
}
function user(req) { return req.session.user || null; }
function requireLogin(req,res,next) {
  if (!user(req)) return res.redirect("/login");
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.session.user.id);
  if (!u || !u.active) { req.session.destroy(()=>{}); return res.redirect("/login"); }
  req.session.user = { id:u.id, username:u.username, name:u.name, role:u.role };
  next();
}
function requireAdmin(req,res,next) {
  if (!user(req) || user(req).role !== "admin") return res.status(403).send("Forbidden");
  next();
}
function getAccessibleCourseIds(uid) {
  return db.prepare("SELECT course_id FROM enrollments WHERE user_id=?").all(uid).map(x=>x.course_id);
}
function canAccessLesson(uid, lessonId) {
  const row = db.prepare(`
    SELECT l.id FROM lessons l
    JOIN enrollments e ON e.course_id=l.course_id
    WHERE l.id=? AND e.user_id=?
  `).get(lessonId, uid);
  return !!row;
}

app.get("/", (req,res) => res.redirect(user(req) ? "/home" : "/login"));

app.get("/login", (req,res) => res.render("login", { error:null }));
app.post("/login", (req,res) => {
  const { username="", password="" } = req.body;
  const u = db.prepare("SELECT * FROM users WHERE username=?").get(username.trim());
  if (!u || !u.active || !bcrypt.compareSync(password, u.password_hash)) {
    return res.status(401).render("login", { error:"Invalid ID/password or account disabled." });
  }
  req.session.user = { id:u.id, username:u.username, name:u.name, role:u.role };
  res.redirect(u.role === "admin" ? "/admin" : "/home");
});
app.post("/logout", (req,res) => req.session.destroy(()=>res.redirect("/login")));

app.get("/home", requireLogin, (req,res) => {
  const uid = user(req).id;
  const courses = db.prepare(`
    SELECT c.*, COUNT(l.id) lesson_count
    FROM courses c
    JOIN enrollments e ON e.course_id=c.id
    LEFT JOIN lessons l ON l.course_id=c.id
    WHERE e.user_id=?
    GROUP BY c.id ORDER BY c.id DESC
  `).all(uid);
  res.render("home", { user:user(req), courses });
});

app.get("/course/:id", requireLogin, (req,res) => {
  const uid=user(req).id, cid=Number(req.params.id);
  const allowed = db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=?").get(uid,cid);
  if (!allowed && user(req).role!=="admin") return res.status(403).send("You do not have access to this course.");
  const course=db.prepare("SELECT * FROM courses WHERE id=?").get(cid);
  if(!course) return res.status(404).send("Course not found");
  const lessons=db.prepare("SELECT * FROM lessons WHERE course_id=? ORDER BY id").all(cid);
  res.render("course",{user:user(req),course,lessons});
});

app.get("/lesson/:id", requireLogin, (req,res) => {
  const id=Number(req.params.id);
  if(user(req).role!=="admin" && !canAccessLesson(user(req).id,id)) return res.status(403).send("Access denied");
  const lesson=db.prepare(`
    SELECT l.*, c.title course_title FROM lessons l JOIN courses c ON c.id=l.course_id WHERE l.id=?
  `).get(id);
  if(!lesson) return res.status(404).send("Lesson not found");
  const resources=db.prepare("SELECT * FROM resources WHERE lesson_id=? ORDER BY id DESC").all(id);
  res.render("lesson",{user:user(req),lesson,resources});
});

app.get("/video/:id", requireLogin, (req,res) => {
  const id=Number(req.params.id);
  if(user(req).role!=="admin" && !canAccessLesson(user(req).id,id)) return res.status(403).send("Access denied");
  const lesson=db.prepare("SELECT video_file FROM lessons WHERE id=?").get(id);
  if(!lesson || !lesson.video_file) return res.status(404).send("Video not uploaded yet.");
  const filePath=path.join(ROOT, lesson.video_file);
  if(!fs.existsSync(filePath)) return res.status(404).send("Video file missing.");
  const stat=fs.statSync(filePath), range=req.headers.range;
  const size=stat.size;
  if(range){
    const [startStr,endStr]=range.replace(/bytes=/,"").split("-");
    const start=parseInt(startStr,10);
    const end=endStr ? parseInt(endStr,10) : size-1;
    if(start>=size || end>=size) return res.status(416).send("Range not satisfiable");
    res.status(206).set({
      "Content-Range":`bytes ${start}-${end}/${size}`,
      "Accept-Ranges":"bytes","Content-Length":end-start+1,"Content-Type":"video/mp4"
    });
    return fs.createReadStream(filePath,{start,end}).pipe(res);
  }
  res.set({"Content-Length":size,"Content-Type":"video/mp4","Accept-Ranges":"bytes"});
  fs.createReadStream(filePath).pipe(res);
});

app.get("/resource/:id", requireLogin, (req,res) => {
  const r=db.prepare(`
    SELECT r.*, l.course_id FROM resources r JOIN lessons l ON l.id=r.lesson_id WHERE r.id=?
  `).get(Number(req.params.id));
  if(!r) return res.status(404).send("Resource not found");
  if(user(req).role!=="admin" && !canAccessLesson(user(req).id,r.lesson_id)) return res.status(403).send("Access denied");
  const fp=path.join(ROOT,r.file_name);
  if(!fs.existsSync(fp)) return res.status(404).send("File missing");
  res.download(fp, r.original_name);
});

app.post("/message", requireLogin, (req,res) => {
  const subject=(req.body.subject||"Problem").trim();
  const body=(req.body.body||"").trim();
  if(body) db.prepare("INSERT INTO messages(user_id,subject,body) VALUES (?,?,?)").run(user(req).id,subject,body);
  res.redirect("/lesson/"+Number(req.body.lesson_id));
});

/* Admin */
app.get("/admin", requireAdmin, (req,res) => {
  const users=db.prepare("SELECT id,username,name,role,active,created_at FROM users ORDER BY id DESC").all();
  const courses=db.prepare("SELECT c.*, COUNT(l.id) lesson_count FROM courses c LEFT JOIN lessons l ON l.course_id=c.id GROUP BY c.id ORDER BY c.id DESC").all();
  const lessons=db.prepare("SELECT l.*,c.title course_title FROM lessons l JOIN courses c ON c.id=l.course_id ORDER BY l.id DESC").all();
  const messages=db.prepare(`
    SELECT m.*,u.username,u.name FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC
  `).all();
  res.render("admin",{user:user(req),users,courses,lessons,messages});
});
app.post("/admin/user", requireAdmin, (req,res) => {
  const {username,name,password,role="user"}=req.body;
  if(!username||!name||!password) return res.redirect("/admin");
  try{
    const hash=bcrypt.hashSync(password,10);
    db.prepare("INSERT INTO users(username,password_hash,name,role) VALUES (?,?,?,?)")
      .run(username.trim(),hash,name.trim(),role==="admin"?"admin":"user");
  }catch(e){}
  res.redirect("/admin");
});
app.post("/admin/user/:id/toggle", requireAdmin, (req,res) => {
  const id=Number(req.params.id);
  if(id!==user(req).id) db.prepare("UPDATE users SET active=1-active WHERE id=?").run(id);
  res.redirect("/admin");
});
app.post("/admin/course", requireAdmin, (req,res) => {
  if(req.body.title) db.prepare("INSERT INTO courses(title,description) VALUES (?,?)").run(req.body.title,req.body.description||"");
  res.redirect("/admin");
});
app.post("/admin/enroll", requireAdmin, (req,res) => {
  try{db.prepare("INSERT OR IGNORE INTO enrollments(user_id,course_id) VALUES (?,?)").run(Number(req.body.user_id),Number(req.body.course_id));}catch(e){}
  res.redirect("/admin");
});
app.post("/admin/lesson", requireAdmin, uploadVideo.single("video"), (req,res) => {
  const result=db.prepare("INSERT INTO lessons(course_id,title,description,video_file) VALUES (?,?,?,?)")
    .run(Number(req.body.course_id),req.body.title,req.body.description||"",req.file?"/uploads/videos/"+req.file.filename:null);
  res.redirect("/admin");
});
app.post("/admin/resource", requireAdmin, uploadResource.single("pdf"), (req,res) => {
  if(req.file) db.prepare("INSERT INTO resources(lesson_id,title,file_name,original_name) VALUES (?,?,?,?)")
    .run(Number(req.body.lesson_id),req.body.title||req.file.originalname,"/public/uploads/resources/"+req.file.filename,req.file.originalname);
  res.redirect("/admin");
});
app.post("/admin/message/:id", requireAdmin, (req,res) => {
  db.prepare("UPDATE messages SET status='closed',admin_reply=? WHERE id=?").run(req.body.reply||"",Number(req.params.id));
  res.redirect("/admin");
});
app.post("/admin/lesson/:id/delete", requireAdmin, (req,res) => {
  const l=db.prepare("SELECT video_file FROM lessons WHERE id=?").get(Number(req.params.id));
  if(l && l.video_file) try{fs.unlinkSync(path.join(ROOT,l.video_file));}catch(e){}
  db.prepare("DELETE FROM lessons WHERE id=?").run(Number(req.params.id));
  res.redirect("/admin");
});
app.post("/admin/resource/:id/delete", requireAdmin, (req,res) => {
  const r=db.prepare("SELECT file_name FROM resources WHERE id=?").get(Number(req.params.id));
  if(r) try{fs.unlinkSync(path.join(ROOT,r.file_name));}catch(e){}
  db.prepare("DELETE FROM resources WHERE id=?").run(Number(req.params.id));
  res.redirect("/admin");
});

app.listen(PORT,()=>console.log(`FS Learning running at http://localhost:${PORT}`));
