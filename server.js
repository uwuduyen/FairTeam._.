const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const path=require("path");
const crypto=require("crypto");

const app=express(), db=new Database(path.join(__dirname,"database","fairteam.db"));
app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"fairteam-change-me",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax"}}));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,name TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,description TEXT,period TEXT,created_by INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS memberships(id INTEGER PRIMARY KEY AUTOINCREMENT,team_id INTEGER NOT NULL,user_id INTEGER NOT NULL,role TEXT NOT NULL CHECK(role IN('leader','member')),position TEXT,UNIQUE(team_id,user_id));
CREATE TABLE IF NOT EXISTS invites(id INTEGER PRIMARY KEY AUTOINCREMENT,team_id INTEGER NOT NULL,email TEXT NOT NULL,role TEXT DEFAULT 'member',position TEXT,token TEXT UNIQUE NOT NULL,status TEXT DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY AUTOINCREMENT,team_id INTEGER NOT NULL,title TEXT NOT NULL,description TEXT,assignee_id INTEGER,creator_id INTEGER NOT NULL,start_date TEXT,deadline TEXT,priority TEXT DEFAULT 'Medium',effort INTEGER DEFAULT 3,status TEXT DEFAULT 'todo',progress INTEGER DEFAULT 0,actual_effort REAL,evidence_link TEXT,evidence_note TEXT,submitted_at TEXT,reviewed_at TEXT,reviewer_id INTEGER,review_status TEXT,review_feedback TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS task_history(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id INTEGER NOT NULL,user_id INTEGER,action TEXT NOT NULL,detail TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS calendar_events(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,team_id INTEGER,type TEXT NOT NULL,title TEXT NOT NULL,date TEXT NOT NULL,description TEXT,meeting_link TEXT,task_id INTEGER);
CREATE TABLE IF NOT EXISTS peer_reviews(id INTEGER PRIMARY KEY AUTOINCREMENT,team_id INTEGER NOT NULL,reviewer_id INTEGER NOT NULL,reviewee_id INTEGER NOT NULL,responsibility INTEGER,punctuality INTEGER,quality INTEGER,collaboration INTEGER,feedback TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(team_id,reviewer_id,reviewee_id));
`);

const q=(sql,p=[])=>db.prepare(sql).all(p), get=(sql,p=[])=>db.prepare(sql).get(p), run=(sql,p=[])=>db.prepare(sql).run(p);
const id=()=>crypto.randomBytes(18).toString("hex");
function auth(req,res,next){if(!req.session.userId)return res.status(401).json({error:"Please log in"});next()}
function member(req,teamId){return get("SELECT * FROM memberships WHERE team_id=? AND user_id=?",[teamId,req.session.userId])}
function leader(req,teamId){const m=member(req,teamId);return m&&m.role==="leader"}
function cleanUser(u){return u&&{id:u.id,email:u.email,name:u.name}}

app.post("/api/auth/signup",async(req,res)=>{
 const {name,email,password}=req.body||{};
 if(!name||!email||!password||password.length<6)return res.status(400).json({error:"Name, email and password (6+ chars) are required"});
 if(get("SELECT id FROM users WHERE email=?",[email.toLowerCase()]))return res.status(409).json({error:"Email already registered"});
 const hash=await bcrypt.hash(password,10), r=run("INSERT INTO users(name,email,password) VALUES(?,?,?)",[name,email.toLowerCase(),hash]);
 req.session.userId=r.lastInsertRowid;res.json({user:cleanUser(get("SELECT * FROM users WHERE id=?",[r.lastInsertRowid]))});
});
app.post("/api/auth/login",async(req,res)=>{
 const u=get("SELECT * FROM users WHERE email=?",[String(req.body.email||"").toLowerCase()]);
 if(!u||!(await bcrypt.compare(req.body.password||"",u.password)))return res.status(401).json({error:"Invalid email or password"});
 req.session.userId=u.id;res.json({user:cleanUser(u)});
});
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",auth,(req,res)=>res.json({user:cleanUser(get("SELECT * FROM users WHERE id=?",[req.session.userId]))}));

app.get("/api/teams",auth,(req,res)=>res.json(q(`SELECT t.*,m.role,m.position,(SELECT COUNT(*) FROM memberships x WHERE x.team_id=t.id) members,(SELECT COUNT(*) FROM tasks x WHERE x.team_id=t.id) tasks
FROM teams t JOIN memberships m ON m.team_id=t.id AND m.user_id=? ORDER BY t.id DESC`,[req.session.userId])));
app.post("/api/teams",auth,(req,res)=>{
 const {name,description="",period="",position="Project Lead"}=req.body;
 if(!name)return res.status(400).json({error:"Team name is required"});
 const r=run("INSERT INTO teams(name,description,period,created_by) VALUES(?,?,?,?)",[name,description,period,req.session.userId]);
 run("INSERT INTO memberships(team_id,user_id,role,position) VALUES(?,?,?,?)",[r.lastInsertRowid,req.session.userId,"leader",position]);
 res.json({id:r.lastInsertRowid});
});
app.get("/api/teams/:id",auth,(req,res)=>{
 const t=get("SELECT * FROM teams WHERE id=?",[req.params.id]); if(!t||!member(req,req.params.id))return res.status(403).json({error:"Access denied"});
 const members=q(`SELECT m.*,u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.team_id=?`,[req.params.id]);
 const tasks=q(`SELECT t.*,u.name assignee_name FROM tasks t LEFT JOIN users u ON u.id=t.assignee_id WHERE t.team_id=? ORDER BY t.deadline`,[req.params.id]);
 res.json({team:t,members,tasks});
});
app.post("/api/teams/:id/invites",auth,(req,res)=>{
 if(!leader(req,req.params.id))return res.status(403).json({error:"Leader only"});
 const email=String(req.body.email||"").toLowerCase(), position=req.body.position||"Member";
 if(!email)return res.status(400).json({error:"Email required"});
 const token=id();run("INSERT INTO invites(team_id,email,position,token) VALUES(?,?,?,?)",[req.params.id,email,position,token]);
 res.json({token,inviteLink:`${req.protocol}://${req.get("host")}/?invite=${token}`});
});
app.get("/api/invites/:token",auth,(req,res)=>{
 const i=get(`SELECT i.*,t.name team_name,u.name inviter FROM invites i JOIN teams t ON t.id=i.team_id JOIN users u ON u.id=t.created_by WHERE i.token=?`,[req.params.token]);
 if(!i)return res.status(404).json({error:"Invite not found"});res.json(i);
});
app.post("/api/invites/:token/accept",auth,(req,res)=>{
 const i=get("SELECT * FROM invites WHERE token=?",[req.params.token]);
 const u=get("SELECT * FROM users WHERE id=?",[req.session.userId]);
 if(!i||i.status!=="pending")return res.status(400).json({error:"Invite unavailable"});
 if(i.email!==u.email)return res.status(403).json({error:"Please log in with the invited email"});
 run("INSERT OR IGNORE INTO memberships(team_id,user_id,role,position) VALUES(?,?,?,?)",[i.team_id,u.id,"member",i.position]);
 run("UPDATE invites SET status='active' WHERE id=?",[i.id]);res.json({ok:true});
});

app.get("/api/tasks",auth,(req,res)=>res.json(q(`SELECT t.*,tm.name team_name,u.name assignee_name FROM tasks t JOIN teams tm ON tm.id=t.team_id LEFT JOIN users u ON u.id=t.assignee_id JOIN memberships m ON m.team_id=t.team_id AND m.user_id=? ORDER BY CASE WHEN t.deadline IS NULL THEN 1 ELSE 0 END,t.deadline`,[req.session.userId])));
app.post("/api/teams/:teamId/tasks",auth,(req,res)=>{
 if(!member(req,req.params.teamId))return res.status(403).json({error:"Access denied"});
 const b=req.body||{};if(!b.title)return res.status(400).json({error:"Task title required"});
 const assignee=b.assignee_id||req.session.userId, effort=Math.min(5,Math.max(1,Number(b.effort||3)));
 const r=run(`INSERT INTO tasks(team_id,title,description,assignee_id,creator_id,start_date,deadline,priority,effort) VALUES(?,?,?,?,?,?,?,?,?)`,
 [req.params.teamId,b.title,b.description||"",assignee,req.session.userId,b.start_date||null,b.deadline||null,b.priority||"Medium",effort]);
 run("INSERT INTO task_history(task_id,user_id,action,detail) VALUES(?,?,?,?)",[r.lastInsertRowid,req.session.userId,"assigned","Task created"]);
 if(b.deadline)run("INSERT INTO calendar_events(user_id,team_id,type,title,date,description,task_id) VALUES(?,?,?,?,?,?,?)",[assignee,req.params.teamId,"task",b.title,b.deadline,b.description||"",r.lastInsertRowid]);
 res.json({id:r.lastInsertRowid});
});
app.get("/api/tasks/:id",auth,(req,res)=>{
 const t=get("SELECT t.*,tm.name team_name,a.name assignee_name,c.name creator_name FROM tasks t JOIN teams tm ON tm.id=t.team_id LEFT JOIN users a ON a.id=t.assignee_id LEFT JOIN users c ON c.id=t.creator_id WHERE t.id=?",[req.params.id]);
 if(!t||!member(req,t.team_id))return res.status(403).json({error:"Access denied"});
 res.json({task:t,history:q(`SELECT h.*,u.name FROM task_history h LEFT JOIN users u ON u.id=h.user_id WHERE h.task_id=? ORDER BY h.id DESC`,[req.params.id])});
});
app.patch("/api/tasks/:id",auth,(req,res)=>{
 const t=get("SELECT * FROM tasks WHERE id=?",[req.params.id]);if(!t||!member(req,t.team_id))return res.status(403).json({error:"Access denied"});
 const b=req.body||{};run(`UPDATE tasks SET title=COALESCE(?,title),description=COALESCE(?,description),deadline=COALESCE(?,deadline),priority=COALESCE(?,priority),effort=COALESCE(?,effort),progress=COALESCE(?,progress) WHERE id=?`,
 [b.title,b.description,b.deadline,b.priority,b.effort,b.progress,t.id]);
 if(b.deadline&&b.deadline!==t.deadline)run("UPDATE calendar_events SET date=? WHERE task_id=?",[b.deadline,t.id]);
 run("INSERT INTO task_history(task_id,user_id,action,detail) VALUES(?,?,?,?)",[t.id,req.session.userId,"updated","Task updated"]);
 res.json({ok:true});
});
app.post("/api/tasks/:id/submit",auth,(req,res)=>{
 const t=get("SELECT * FROM tasks WHERE id=?",[req.params.id]);if(!t||t.assignee_id!==req.session.userId)return res.status(403).json({error:"Only the assignee can submit"});
 if(!req.body.evidence_link&&!req.body.evidence_note)return res.status(400).json({error:"Evidence link or description is required"});
 run(`UPDATE tasks SET status='pending_review',evidence_link=?,evidence_note=?,actual_effort=?,submitted_at=CURRENT_TIMESTAMP,review_status='pending' WHERE id=?`,
 [req.body.evidence_link||"",req.body.evidence_note||"",req.body.actual_effort||null,t.id]);
 run("INSERT INTO task_history(task_id,user_id,action,detail) VALUES(?,?,?,?)",[t.id,req.session.userId,"submitted","Evidence submitted for leader review"]);
 res.json({ok:true});
});
app.post("/api/tasks/:id/review",auth,(req,res)=>{
 const t=get("SELECT * FROM tasks WHERE id=?",[req.params.id]);if(!t||!leader(req,t.team_id)||t.assignee_id===req.session.userId)return res.status(403).json({error:"A leader cannot verify their own task"});
 const {decision,feedback}=req.body;if(!["verified","changes_requested"].includes(decision)||!feedback)return res.status(400).json({error:"Decision and feedback are required"});
 const status=decision==="verified"?"verified":"changes_requested";
 run("UPDATE tasks SET status=?,review_status=?,review_feedback=?,reviewer_id=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",[status,decision,feedback,req.session.userId,t.id]);
 run("INSERT INTO task_history(task_id,user_id,action,detail) VALUES(?,?,?,?)",[t.id,req.session.userId,decision,feedback]);
 res.json({ok:true});
});

app.get("/api/calendar",auth,(req,res)=>res.json(q(`SELECT e.*,tm.name team_name FROM calendar_events e LEFT JOIN teams tm ON tm.id=e.team_id WHERE e.user_id=? OR (e.team_id IN (SELECT team_id FROM memberships WHERE user_id=?) AND e.type<>'personal') ORDER BY e.date`,[req.session.userId,req.session.userId])));
app.post("/api/calendar",auth,(req,res)=>{
 const b=req.body||{};if(!b.title||!b.date||!b.type)return res.status(400).json({error:"Title, date and type required"});
 const r=run("INSERT INTO calendar_events(user_id,team_id,type,title,date,description,meeting_link,task_id) VALUES(?,?,?,?,?,?,?,?)",[req.session.userId,b.team_id||null,b.type,b.title,b.date,b.description||"",b.meeting_link||"",b.task_id||null]);res.json({id:r.lastInsertRowid});
});
app.delete("/api/calendar/:id",auth,(req,res)=>{
 const e=get("SELECT * FROM calendar_events WHERE id=?",[req.params.id]);if(!e)return res.status(404).json({error:"Not found"});
 if(e.team_id&&!leader(req,e.team_id)&&e.user_id!==req.session.userId)return res.status(403).json({error:"Not allowed"});
 run("DELETE FROM calendar_events WHERE id=?",[e.id]);res.json({ok:true});
});

app.get("/api/teams/:id/reviews",auth,(req,res)=>{
 if(!member(req,req.params.id))return res.status(403).json({error:"Access denied"});
 const rows=q(`SELECT r.*,u.name reviewee_name FROM peer_reviews r JOIN users u ON u.id=r.reviewee_id WHERE r.team_id=? AND r.reviewee_id=?`,[req.params.id,req.session.userId]);
 res.json(rows);
});
app.post("/api/teams/:id/reviews",auth,(req,res)=>{
 const teamId=req.params.id;if(!member(req,teamId))return res.status(403).json({error:"Access denied"});
 const b=req.body||{};if(!b.reviewee_id||b.reviewee_id==req.session.userId)return res.status(400).json({error:"Choose another member"});
 const vals=[b.responsibility,b.punctuality,b.quality,b.collaboration].map(Number);
 if(vals.some(v=>v<1||v>5))return res.status(400).json({error:"Scores must be 1-5"});
 run(`INSERT INTO peer_reviews(team_id,reviewer_id,reviewee_id,responsibility,punctuality,quality,collaboration,feedback) VALUES(?,?,?,?,?,?,?,?)
 ON CONFLICT(team_id,reviewer_id,reviewee_id) DO UPDATE SET responsibility=excluded.responsibility,punctuality=excluded.punctuality,quality=excluded.quality,collaboration=excluded.collaboration,feedback=excluded.feedback`,
 [teamId,req.session.userId,b.reviewee_id,...vals,b.feedback||""]);res.json({ok:true});
});
app.get("/api/teams/:id/contribution",auth,(req,res)=>{
 const teamId=req.params.id;if(!member(req,teamId))return res.status(403).json({error:"Access denied"});
 const members=q("SELECT m.user_id,u.name,m.role,m.position FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.team_id=?",[teamId]);
 const result=members.map(m=>{
   const tasks=q("SELECT * FROM tasks WHERE team_id=? AND assignee_id=?",[teamId,m.user_id]);
   const verified=tasks.filter(t=>t.status==="verified").length, total=tasks.length;
   const quality=total?verified/total*100:0, reliability=total?tasks.reduce((s,t)=>s+(t.status==="verified"&&t.submitted_at&&t.deadline&&t.submitted_at.slice(0,10)<=t.deadline?100:0),0)/total:0;
   const effort=total?Math.min(100,tasks.reduce((s,t)=>s+(Number(t.effort)||3),0)/(total*5)*100):0;
   const peers=q("SELECT responsibility,punctuality,quality,collaboration FROM peer_reviews WHERE team_id=? AND reviewee_id=?",[teamId,m.user_id]);
   const peer=peers.length?peers.reduce((s,r)=>s+(r.responsibility+r.punctuality+r.quality+r.collaboration)/20*100,0)/peers.length:0;
   const score=Math.round(quality*.30+effort*.30+reliability*.20+peer*.20);
   return {...m,total,verified,score};
 });
 const sum=result.reduce((s,x)=>s+x.score,0)||1;result.forEach(x=>x.contribution=Math.round(x.score/sum*1000)/10);res.json(result);
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=process.env.PORT||3000;app.listen(port,()=>console.log(`FairTeam running on http://localhost:${port}`));
