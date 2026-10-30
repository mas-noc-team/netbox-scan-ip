# Python Network Scanner & NetBox Synchronizer

Alat otomatisasi pemindaian jaringan (*Network Scanner*) berbasis Python yang menggunakan **Scapy** untuk mendeteksi perangkat aktif, port terbuka, sistem operasi, serta nama host secara presisi (termasuk kueri mDNS & LLMNR). Skrip ini terintegrasi secara langsung dengan REST API **NetBox** (IPAM/DCIM) dan dilengkapi sistem notifikasi real-time via **Telegram Bot**.

---

## 🚀 Fitur Utama

- **Network Discovery & ARP Scanning**: Memindai seluruh subnet IP (misal: `192.168.x.0/24`) secara paralel (*Multithreading*).
- **Advanced Hostname Detection**: Menggabungkan Reverse DNS, NetBIOS, mDNS (Bonjour), dan LLMNR untuk menangkap nama asli perangkat (seperti *Realme*, *Infinix*, *Galaxy*, dll.).
- **MAC Vendor & OS Fingerprinting**: Identifikasi pabrikan perangkat berdasarkan database OUI dan deteksi OS berdasarkan nilai TTL.
- **NetBox API Integration**: 
  - Otomatis membuat tag *Role* jika belum terdaftar.
  - Sinkronisasi otomatis (*POST* untuk perangkat baru, *PATCH* untuk pembaruan).
  - Klasifikasi otomatis antara *Device* fisik atau *Virtual Machine* (Proxmox/VMware).
  - Rekonsiliasi cerdas: Mengosongkan alokasi IP yang mati/offline tanpa mengubah statusnya menjadi deprecated.
- **Telegram Notifications**: Mengirimkan peringatan instan saat perangkat baru terhubung atau ketika perangkat mendadak offline.


---

## 🛠️ Persyaratan Sistem

- Python 3.10 atau versi terbaru.
- Hak akses Administrator / Superuser (`sudo` di Linux/macOS atau *Run as Administrator* di Windows) untuk modul `scapy` (*raw sockets*).
- Server NetBox aktif (lokal atau remote).

---

## 📦 Panduan Instalasi & Menjalankan

### 1. Kloning & Masuk ke Direktori Proyek
```bash
git clone https://github.com/mas-noc-team/netbox-scan-ip
cd netbox-scan-ip
```

### 2. Konfigurasi Virtual Environment (Venv)

#### **Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install scapy requests mac-vendor-lookup urllib3
```

#### **Windows (Command Prompt / PowerShell):**
*Scapy di Windows sangat bergantung pada driver penangkap paket. Pastikan Anda menginstall Npcap (bukan WinPcap lama).

```bash
python -m venv venv
venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install scapy requests mac-vendor-lookup urllib3
```

## ⚙️ Cara Penggunaan (Usage)

Pastikan *Virtual Environment* sudah aktif, lalu jalankan skrip menggunakan hak akses administrator:

### **Linux / macOS:**
```bash
python net_scanner-netbox-service.py -t 192.168.x.0/24 ^
  -p "22,53,80,8080,8000,443,3389" ^
  --netbox-url "http://127.0.0.1:8000" ^
  --netbox-token "YOUR_NETBOX_API_TOKEN" ^
  --telegram-token "YOUR_TELEGRAM_BOT_TOKEN" ^
  --telegram-chat "YOUR_TELEGRAM_CHAT_ID"
```

### **Windows (CMD / PowerShell sebagai Administrator):**
*Tentukan Interface Jaringan Secara Manual:
```cmd
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

```cmd
python net_scanner-netbox-service.py -t 192.168.x.0/24 `
   -p "22,53,80,8080,8000,443,3389" `
  --netbox-url "http://127.0.0.1:8000" `
  --netbox-token "YOUR_NETBOX_API_TOKEN" `
  --telegram-token "YOUR_TELEGRAM_BOT_TOKEN" `
  --telegram-chat "YOUR_TELEGRAM_CHAT_ID"
```
---

## ⏰ Otomatisasi Harian (Cron Job / Task Scheduler)
```bash
sudo crontab -e
```
```bash
# Misal dijalankan pukul 02:00 pagi setiap hari
0 2 * * * /path/to/venv/bin/python3 /path/to/net_scanner-netbox-service.py -t 192.168.x.0/24 --netbox-url "[http://127.0.0.1:8000](http://127.0.0.1:8000)" --netbox-token "YOUR_TOKEN" --telegram-token "YOUR_TELE_TOKEN" --telegram-chat "YOUR_CHAT_ID" >> /var/log/scanner_cron.log 2>&1
```
---

## 📄 Lisensi
Proyek ini dilisensikan di bawah [MIT License](LICENSE).

