const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false }
});

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "replace-this-before-deploying",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" }
}));
app.use(express.static(path.join(__dirname, "../public")));

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@geex.local").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      role TEXT NOT NULL DEFAULT 'user', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS services(
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
      price NUMERIC(12,4) NOT NULL CHECK(price > 0),
      provider_service_id TEXT, active BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS orders(
      id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id),
      service_id BIGINT NOT NULL REFERENCES services(id), link TEXT NOT NULL,
      quantity INTEGER NOT NULL, charge NUMERIC(12,2) NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending', provider_order_id TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS deposits(
      id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id),
      amount NUMERIC(12,2) NOT NULL, sender TEXT NOT NULL, reference TEXT,
      status TEXT NOT NULL DEFAULT 'Pending', created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  const admin = await pool.query("SELECT id FROM users WHERE email=$1", [ADMIN_EMAIL]);
  if (!admin.rowCount) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    await pool.query(
      "INSERT INTO users(name,email,password,role) VALUES($1,$2,$3,'admin')",
      ["GEEX Admin", ADMIN_EMAIL, hash]
    );
  }
  const count = await pool.query("SELECT COUNT(*)::int AS n FROM services");
  if (count.rows[0].n === 0) {
    const seeds = [
      ["Instagram Followers","Instagram",25],["Instagram Likes","Instagram",8],
      ["TikTok Followers","TikTok",35],["TikTok Views","TikTok",3],
      ["Facebook Followers","Facebook",22],["YouTube Views","YouTube",12]
    ];
    for (const s of seeds) {
      await pool.query("INSERT INTO services(name,category,price) VALUES($1,$2,$3)", s);
    }
  }
}

const requireUser = (req,res,next) => req.session.user ? next() : res.status(401).json({error:"سجل الدخول أولاً"});
const requireAdmin = (req,res,next) => req.session.user?.role === "admin" ? next() : res.status(403).json({error:"غير مصرح"});
const safeUser = u => ({id:u.id,name:u.name,email:u.email,balance:Number(u.balance),role:u.role});

app.post("/api/register", async (req,res) => {
  try {
    const {name,email,password} = req.body || {};
    if (!name || !email || !password || password.length < 8)
      return res.status(400).json({error:"أدخل البيانات كاملة وكلمة مرور 8 أحرف على الأقل"});
    const hash = bcrypt.hashSync(password,10);
    const result = await pool.query(
      "INSERT INTO users(name,email,password) VALUES($1,$2,$3) RETURNING *",
      [name,email.toLowerCase(),hash]
    );
    req.session.user = safeUser(result.rows[0]);
    res.json({user:req.session.user});
  } catch(e) { res.status(400).json({error:"البريد الإلكتروني مستخدم بالفعل"}); }
});

app.post("/api/login", async (req,res) => {
  const {email,password} = req.body || {};
  const result = await pool.query("SELECT * FROM users WHERE email=$1",[(email||"").toLowerCase()]);
  const u = result.rows[0];
  if (!u || !bcrypt.compareSync(password||"",u.password))
    return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
  req.session.user = safeUser(u);
  res.json({user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",requireUser,async(req,res)=>{
  const r=await pool.query("SELECT * FROM users WHERE id=$1",[req.session.user.id]);
  if(!r.rowCount) return res.status(401).json({error:"الحساب غير موجود"});
  res.json({user:safeUser(r.rows[0])});
});
app.get("/api/services",requireUser,async(req,res)=>{
  const r=await pool.query("SELECT id,name,category,price FROM services WHERE active=TRUE ORDER BY category,name");
  res.json({services:r.rows});
});
app.get("/api/orders",requireUser,async(req,res)=>{
  const r=await pool.query(
    "SELECT o.*,s.name AS service FROM orders o JOIN services s ON s.id=o.service_id WHERE o.user_id=$1 ORDER BY o.id DESC",
    [req.session.user.id]
  );
  res.json({orders:r.rows});
});
app.post("/api/orders",requireUser,async(req,res)=>{
  const {service_id,link,quantity}=req.body||{};
  const q=Number(quantity);
  if(!link || !Number.isInteger(q) || q<1 || q>1000000)
    return res.status(400).json({error:"راجع الرابط والكمية"});
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const sr=await client.query("SELECT * FROM services WHERE id=$1 AND active=TRUE FOR SHARE",[Number(service_id)]);
    if(!sr.rowCount) throw new Error("الخدمة غير متاحة");
    const service=sr.rows[0];
    const charge=Number((Number(service.price)*q/1000).toFixed(2));
    const ur=await client.query("SELECT balance FROM users WHERE id=$1 FOR UPDATE",[req.session.user.id]);
    if(Number(ur.rows[0].balance)<charge) throw new Error("رصيدك غير كافٍ");
    await client.query("UPDATE users SET balance=balance-$1 WHERE id=$2",[charge,req.session.user.id]);
    const or=await client.query(
      "INSERT INTO orders(user_id,service_id,link,quantity,charge) VALUES($1,$2,$3,$4,$5) RETURNING id",
      [req.session.user.id,service.id,link,q,charge]
    );
    await client.query("COMMIT");
    res.json({ok:true,order_id:or.rows[0].id,charge});
  } catch(e) {
    await client.query("ROLLBACK");
    res.status(400).json({error:e.message||"تعذر إنشاء الطلب"});
  } finally { client.release(); }
});
app.post("/api/deposits",requireUser,async(req,res)=>{
  const {amount,sender,reference}=req.body||{};
  if(!Number.isFinite(Number(amount))||Number(amount)<10||!sender)
    return res.status(400).json({error:"أدخل مبلغاً صحيحاً ورقم المحول"});
  const r=await pool.query(
    "INSERT INTO deposits(user_id,amount,sender,reference) VALUES($1,$2,$3,$4) RETURNING id",
    [req.session.user.id,Number(amount),sender,reference||""]
  );
  res.json({ok:true,deposit_id:r.rows[0].id,message:"تم إرسال طلب الشحن للمراجعة"});
});
app.get("/api/admin/overview",requireUser,requireAdmin,async(req,res)=>{
  const [users,orders,deposits,services]=await Promise.all([
    pool.query("SELECT id,name,email,balance FROM users WHERE role='user' ORDER BY id DESC"),
    pool.query("SELECT o.*,u.name AS customer,s.name AS service FROM orders o JOIN users u ON u.id=o.user_id JOIN services s ON s.id=o.service_id ORDER BY o.id DESC LIMIT 100"),
    pool.query("SELECT d.*,u.name AS customer FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.id DESC"),
    pool.query("SELECT * FROM services ORDER BY id")
  ]);
  res.json({users:users.rows,orders:orders.rows,deposits:deposits.rows,services:services.rows});
});
app.post("/api/admin/deposits/:id/approve",requireUser,requireAdmin,async(req,res)=>{
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const d=await client.query("SELECT * FROM deposits WHERE id=$1 AND status='Pending' FOR UPDATE",[Number(req.params.id)]);
    if(!d.rowCount) throw new Error("الطلب غير موجود أو تمت مراجعته");
    await client.query("UPDATE deposits SET status='Approved' WHERE id=$1",[d.rows[0].id]);
    await client.query("UPDATE users SET balance=balance+$1 WHERE id=$2",[d.rows[0].amount,d.rows[0].user_id]);
    await client.query("COMMIT"); res.json({ok:true});
  } catch(e) { await client.query("ROLLBACK"); res.status(400).json({error:e.message}); }
  finally { client.release(); }
});
app.post("/api/admin/services",requireUser,requireAdmin,async(req,res)=>{
  const {name,category,price,provider_service_id}=req.body||{};
  if(!name||!category||Number(price)<=0) return res.status(400).json({error:"بيانات الخدمة غير مكتملة"});
  await pool.query("INSERT INTO services(name,category,price,provider_service_id) VALUES($1,$2,$3,$4)",
    [name,category,Number(price),provider_service_id||null]);
  res.json({ok:true});
});
app.post("/api/admin/orders/:id/status",requireUser,requireAdmin,async(req,res)=>{
  const allowed=["Pending","Processing","Completed","Partial","Canceled","Failed"];
  if(!allowed.includes(req.body.status)) return res.status(400).json({error:"حالة غير صحيحة"});
  await pool.query("UPDATE orders SET status=$1 WHERE id=$2",[req.body.status,Number(req.params.id)]);
  res.json({ok:true});
});
app.post("/api/admin/provider/test",requireUser,requireAdmin,async(req,res)=>{
  const url=process.env.SMM_PROVIDER_URL, key=process.env.SMM_PROVIDER_KEY;
  if(!url||!key) return res.status(400).json({error:"أضف بيانات المزود في إعدادات Secrets على الاستضافة أولاً"});
  try {
    const response=await fetch(url,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:new URLSearchParams({key,action:"services"})});
    const data=await response.json();
    res.json({ok:response.ok,services_count:Array.isArray(data)?data.length:null,preview:Array.isArray(data)?data.slice(0,3):data});
  } catch(e) { res.status(502).json({error:"تعذر الاتصال بمزود الخدمة"}); }
});

const port=process.env.PORT||3000;
initDb().then(()=>app.listen(port,()=>console.log(`GEEX panel running on ${port}`)))
  .catch(e=>{console.error("Database initialization failed",e);process.exit(1);});
