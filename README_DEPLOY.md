# คู่มือการติดตั้งระบบ Auto HTML Upload & Project Hosting บน Server IP 178.128.59.217

ระบบนี้ถูกพัฒนาด้วย Node.js + Express เพื่อรองรับการ Upload ไฟล์ HTML หรือ ZIP Package และให้บริการ URL อัตโนมัติในรูปแบบ `http://178.128.59.217/projects/<project-slug>`

---

## 🛠️ 1. เตรียม Server (Ubuntu / Debian VPS)

เชื่อมต่อเข้า Server ผ่าน SSH:
```bash
ssh root@178.128.59.217
```

ติดตั้ง Node.js 18 LTS, Unzip และ PM2 Process Manager:
```bash
# Update System
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl unzip git

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install PM2 Process Manager (เพื่อให้แอปทำงานเบื้องหลังตลอดเวลา และ auto restart เมื่อ reboot)
sudo npm install -g pm2
```

---

## 📁 2. นำไฟล์โครงการไปลง Server

สร้างโฟลเดอร์โครงการ:
```bash
mkdir -p /var/www/nct-web
cd /var/www/nct-web
```

ก๊อปปี้ไฟล์ทั้งหมดจากเครื่องของคุณขึ้น Server (หรือใช้ SCP / SFTP / Git):
```bash
# ตัวอย่างการใช้ SCP จากเครื่อง local:
scp -r d:/00_NCT/00\ Web/* root@178.128.59.217:/var/www/nct-web/
```

สั่งติดตั้ง Dependencies บน Server:
```bash
cd /var/www/nct-web
npm install
```

---

## 🚀 3. เริ่มรันบริการด้วย PM2

```bash
# สั่งเริ่มรันแอปพลิเคชัน
pm2 start server.js --name "nct-web-uploader"

# บันทึกสถานะเพื่อให้เปิดอัตโนมัติเมื่อ Server Restart
pm2 save
pm2 startup
```

ตอนนี้ระบบพร้อมใช้งานทันทีที่: `http://178.128.59.217:3000`

---

## 🌐 4. ตั้งค่า Nginx Reverse Proxy (เชื่อมต่อกับ Domain / Subdomain)

จากภาพ DNS Record ของคุณ ที่มีการชี้ A Record มายัง IP `178.128.59.217` (เช่น `bems`, `tracker` หรือหากเพิ่ม subdomain ใหม่ เช่น `deploy` / `projects`)

คุณสามารถตั้งค่า Nginx ให้รองรับทั้ง IP หรือ Domain/Subdomain ได้ง่ายๆ:

ติดตั้ง Nginx:
```bash
sudo apt install -y nginx
```

แก้ไขไฟล์ Nginx Configuration:
```bash
sudo nano /etc/nginx/sites-available/default
```

วางคอนฟิกนี้ (เปลี่ยน `yourdomain.com` เป็นโดเมนจริงของคุณ เช่น `deploy.nctprosperatech.com`):
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    # ใส่ Domain / Subdomain หรือ IP Server
    server_name 178.128.59.217 deploy.nctprosperatech.com *.nctprosperatech.com;

    # เพิ่มขนาดไฟล์อัปโหลดสูงสุดเป็น 100MB
    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

ตรวจสอบความถูกต้องและ Restart Nginx:
```bash
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🎉 สรุปการใช้งาน

- **หน้าบริหารจัดการ Upload:** `http://178.128.59.217/` หรือ `http://deploy.yourdomain.com/`
- **URL โปรเจกต์ที่อัปโหลด:** `http://178.128.59.217/projects/ชื่อโปรเจกต์` หรือ `http://deploy.yourdomain.com/projects/ชื่อโปรเจกต์`

