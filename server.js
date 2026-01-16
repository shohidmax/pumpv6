const WebSocket = require('ws');
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

// ==========================================
// CONFIGURATION
// ==========================================
// আপনার দেওয়া MongoDB কানেকশন স্ট্রিং
const MONGODB_URI = "mongodb+srv://sarwarjahanshohid_db_user:CPlQyNRqiD2CyRNc@cluster0.t1fleow.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const JWT_SECRET = process.env.JWT_SECRET || "secure_secret_key_500_devices";
const PORT = process.env.PORT || 3000;

// অফলাইন চেক কনফিগারেশন (১০ মিনিট)
const OFFLINE_CHECK_INTERVAL = 10 * 60 * 1000; 
const OFFLINE_THRESHOLD = 10 * 60 * 1000;      

mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch(err => console.error("❌ DB Error:", err));

// ==========================================
// SCHEMAS
// ==========================================

const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    isBlocked: { type: Boolean, default: false },
    devices: [{ type: String }] // Array of MAC Addresses
});

const DeviceSchema = new mongoose.Schema({
    macAddress: { type: String, unique: true, required: true },
    serialNumber: { type: String, required: true }, 
    ownerEmail: { type: String, default: null },
    isLocked: { type: Boolean, default: false },
    status: { type: String, default: 'OFFLINE' },
    lastSeen: { type: Date, default: Date.now }
});

const MotorLogSchema = new mongoose.Schema({
    macAddress: { type: String, required: true, index: true },
    startTime: Date,
    endTime: Date,
    duration: String,
    bdDate: String,       
    bdTime: String,       
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Device = mongoose.model('Device', DeviceSchema);
const MotorLog = mongoose.model('MotorLog', MotorLogSchema);

// ==========================================
// EXPRESS APP
// ==========================================
const app = express();
app.use(cors());
app.use(express.json());

// --- FRONTEND SERVING ---
// সার্ভার এখন রুট ফোল্ডার থেকে ফাইল সার্ভ করবে (index.html সহ)
app.use(express.static(__dirname));

// কেউ রুট URL হিট করলে index.html দেখাবে
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- Helper: BD Time ---
function getBDTime() {
    const now = new Date();
    const options = { timeZone: 'Asia/Dhaka', hour12: true };
    return {
        date: now.toLocaleDateString('en-GB', { timeZone: 'Asia/Dhaka' }),
        time: now.toLocaleTimeString('en-US', options)
    };
}

// --- Helper: Generate Serial ---
function generateSerialNumber() {
    return `SN-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

// --- Offline Checker ---
async function checkOfflineDevices() {
    try {
        const threshold = new Date(Date.now() - OFFLINE_THRESHOLD);
        const result = await Device.updateMany(
            { status: 'ONLINE', lastSeen: { $lt: threshold } },
            { $set: { status: 'OFFLINE' } }
        );
        if (result.modifiedCount > 0) {
            console.log(`[Offline Monitor] ${result.modifiedCount} devices marked OFFLINE.`);
        }
    } catch (error) {
        console.error('[Offline Monitor Error]', error);
    }
}
setInterval(checkOfflineDevices, OFFLINE_CHECK_INTERVAL);

// --- Middleware ---
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ msg: "No token" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) { res.status(401).json({ msg: "Invalid Token" }); }
};

// --- ROUTES ---

// Signup
app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        res.json({ msg: "User registered" });
    } catch (e) { res.status(400).json({ msg: "Email exists" }); }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "User not found" });
    if (user.isBlocked) return res.status(403).json({ msg: "Account Blocked" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid Credentials" });

    const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, JWT_SECRET);
    res.json({ token, user: { name: user.name, email: user.email, role: user.role, devices: user.devices } });
});

// Add Device
app.post('/api/device/add', authenticate, async (req, res) => {
    const { macAddress, serialNumber } = req.body;
    
    let device = await Device.findOne({ macAddress });
    
    // ডিভাইস আগে সার্ভারে কানেক্ট না হলে অ্যাড করা যাবে না
    if (!device) return res.status(404).json({ msg: "Device not found in server. Connect it first." });
    
    // সিরিয়াল নম্বর ভেরিফিকেশন
    if (device.serialNumber !== serialNumber) return res.status(400).json({ msg: "Invalid Serial Number" });
    
    // অলরেডি ক্লেইম করা কিনা চেক
    if (device.ownerEmail && device.ownerEmail !== req.user.email) return res.status(400).json({ msg: "Device already claimed" });

    device.ownerEmail = req.user.email;
    await device.save();

    await User.findByIdAndUpdate(req.user.id, { $addToSet: { devices: macAddress } });
    res.json({ msg: "Device Added", macAddress });
});

// Admin: Get Users
app.get('/api/admin/users', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ msg: "Access Denied" });
    res.json(await User.find({}, '-password'));
});

// Admin: Block/Unblock
app.post('/api/admin/toggle-block', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ msg: "Access Denied" });
    await User.findByIdAndUpdate(req.body.userId, { isBlocked: req.body.blockStatus });
    res.json({ msg: "Updated" });
});

// Admin: Lock Device
app.post('/api/admin/lock-device', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ msg: "Access Denied" });
    const { macAddress, lockStatus } = req.body;
    await Device.findOneAndUpdate({ macAddress }, { isLocked: lockStatus });
    
    if (lockStatus) {
        const ws = connectedDevices.get(macAddress);
        if (ws) {
            ws.send(JSON.stringify({ command: "LOCKED_BY_ADMIN" }));
            ws.close();
        }
    }
    res.json({ msg: "Updated" });
});

// ==========================================
// WEBSOCKET SERVER
// ==========================================
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const connectedDevices = new Map();
const activeMotorSessions = new Map();

wss.on('connection', (ws) => {
    ws.on('message', async (msg) => {
        try {
            const data = JSON.parse(msg);

            // 1. Identify Device (ESP32 First Connect)
            if (data.type === 'identify_device') {
                const mac = data.macAddress;
                let deviceDB = await Device.findOne({ macAddress: mac });
                
                if (!deviceDB) {
                    // নতুন ডিভাইস: অটো সিরিয়াল জেনারেট করুন
                    const newSerial = generateSerialNumber();
                    deviceDB = new Device({
                        macAddress: mac,
                        serialNumber: newSerial,
                        status: 'ONLINE',
                        lastSeen: new Date()
                    });
                    await deviceDB.save();
                    console.log(`✨ New Device: ${mac} (SN: ${newSerial})`);
                } else {
                    // লক চেক
                    if (deviceDB.isLocked) {
                        ws.send(JSON.stringify({ command: "LOCKED_BY_ADMIN" }));
                        return ws.close();
                    }
                    deviceDB.status = 'ONLINE';
                    deviceDB.lastSeen = new Date();
                    await deviceDB.save();
                }
                connectedDevices.set(mac, ws);
            }

            // 2. Status Update (ESP32)
            else if (data.type === 'statusUpdate') {
                const p = data.payload;
                const mac = p.macAddress;
                
                // আপডেট লাস্ট সিন
                await Device.updateOne({ macAddress: mac }, { lastSeen: new Date(), status: 'ONLINE' });

                // মোটর লজিক ও লগিং
                if (p.motorStatus === "ON") {
                    if (!activeMotorSessions.has(mac)) activeMotorSessions.set(mac, new Date());
                } 
                else if (p.motorStatus === "OFF") {
                    const startTime = activeMotorSessions.get(mac);
                    if (startTime) {
                        const endTime = new Date();
                        const durationMs = endTime - startTime;
                        
                        const mins = Math.floor(durationMs / 60000);
                        const secs = Math.floor((durationMs % 60000) / 1000);
                        const bdInfo = getBDTime();

                        const newLog = new MotorLog({
                            macAddress: mac, startTime, endTime,
                            duration: `${mins}m ${secs}s`,
                            bdDate: bdInfo.date, bdTime: bdInfo.time
                        });
                        await newLog.save();
                        activeMotorSessions.delete(mac);
                    }
                }
                
                // ড্যাশবোর্ডে ব্রডকাস্ট
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify(data));
                });
            }

            // 3. User Commands (Start/Stop)
            else if (data.type === 'command') {
                const targetMac = data.targetMac;
                const dev = await Device.findOne({ macAddress: targetMac });
                if (dev && dev.isLocked) return;

                const targetWs = connectedDevices.get(targetMac);
                if (targetWs && targetWs.readyState === WebSocket.OPEN) {
                    targetWs.send(JSON.stringify({ command: data.command, value: data.value }));
                }
            }
            
            // 4. Get Logs (Dashboard Request)
            else if (data.command === 'GET_LOGS') {
                const logs = await MotorLog.find({ macAddress: data.macAddress }).sort({ createdAt: -1 }).limit(50);
                ws.send(JSON.stringify({ type: 'logListUpdate', payload: logs }));
            }

        } catch (e) { console.error(e); }
    });
});

server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));