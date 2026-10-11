# MikroTik User Manager

Aplikasi self-hosted untuk mengelola Simple Queue, bandwidth, trafik, dan isolasi akses pelanggan pada MikroTik RouterOS v6/v7. Antarmuka berbahasa Indonesia, responsif untuk ponsel/tablet/desktop, dan mendukung instalasi PWA.

## Fitur awal

- Dashboard status router, jumlah queue, alamat terisolasi, dan aktivitas hari ini.
- Status pelanggan dari kondisi aktual queue/firewall, pencarian nama/IP/queue, dan refresh otomatis setiap 15 detik.
- Bulk isolation/restore sampai 100 pelanggan per proses, dengan konfirmasi dan verifikasi per pelanggan.
- Pengumpulan rate upload/download ke SQLite setiap 60 detik, grafik per jam/hari/bulan, serta retensi sampel 31 hari.
- Multi-router dengan tes koneksi RouterOS API.
- Daftar Simple Queue: tambah, edit, hapus, aktif/nonaktif.
- Isolasi dan pemulihan pelanggan melalui address-list khusus aplikasi.
- Riwayat isolasi/pemulihan setelah operasi diverifikasi pada router.
- SQLite persisten dalam Docker volume, tidak menyimpan data operasional di localStorage/IndexedDB.
- Kredensial router dienkripsi AES-256-GCM sebelum disimpan.
- Docker Compose dan skrip deployment deploy.sh.
- PWA shell caching; endpoint API tidak dicache.

## Deployment cepat di server Linux

Persyaratan: Git, Docker Engine, Docker Compose plugin, dan OpenSSL.

~~~bash
git clone https://github.com/rskabc/user-manager.git
cd user-manager
chmod +x deploy.sh
./deploy.sh
~~~

Pada deployment pertama, script membuat .env, secret JWT, kunci enkripsi, dan password admin acak. **Simpan password yang dicetak script.** File .env dibuat dengan permission terbatas dan tidak boleh di-commit.

Aplikasi default tersedia pada port **8300**:

~~~text
http://IP-SERVER:8300
~~~

Jika menggunakan reverse proxy, arahkan upstream ke port 8300. Gunakan HTTPS di reverse proxy sebelum login dari jaringan yang tidak tepercaya. Port aplikasi sebaiknya tidak dibuka langsung ke internet tanpa TLS/access control.

Untuk deployment berikutnya:

~~~bash
./deploy.sh
~~~

Script menjalankan git pull --ff-only, build image, lalu docker compose up -d. Log:

~~~bash
docker compose logs -f --tail=100
~~~

## Konfigurasi MikroTik

1. Pastikan RouterOS API dapat diakses dari IP server aplikasi.
2. Buat akun khusus untuk aplikasi dengan hak minimum yang sesuai.
3. Aktifkan service API (port default 8728) atau API-SSL sesuai kebutuhan.
4. Batasi akses service API di firewall RouterOS hanya dari IP server aplikasi. Jangan mengekspos API ke internet publik.
5. Tambahkan router dari UI dan tes koneksi.

Nama address-list isolasi default: USER_MANAGER_ISOLATED. Dapat diubah melalui MIKROTIK_ISOLATION_LIST di .env sebelum menjalankan aplikasi.

### Firewall isolation rule — wajib dikonfigurasi manual

Aplikasi hanya menambah/menghapus entry pada address-list khususnya. Aplikasi **tidak** membuat, mengubah, atau menghapus firewall filter rule secara otomatis. Untuk memblokir trafik pelanggan, siapkan rule drop sesuai desain jaringan Anda, letakkan sebelum rule accept yang relevan, dan uji pada pelanggan percobaan.

Contoh konsep rule IPv4 RouterOS (sesuaikan interface, urutan, dan kebijakan jaringan terlebih dahulu):

~~~routeros
/ip/firewall/filter/add chain=forward src-address-list=USER_MANAGER_ISOLATED action=drop comment="User Manager isolation"
~~~

Rule contoh di atas bukan konfigurasi universal. Pertimbangkan IPv6, trafik ke router itu sendiri, fasttrack, VLAN/bridge, queue type, dan aturan accept yang telah ada. Jangan tempel rule tanpa memahami urutan firewall di router produksi. Uji dan verifikasi dengan administrator jaringan.

## Data dan keamanan

- Database: volume Docker user_manager_data, file /data/user-manager.sqlite.
- Jangan menghapus volume saat menjalankan deployment.
- JWT_SECRET digunakan untuk token sesi; APP_ENCRYPTION_KEY mengenkripsi password router. **Jangan mengganti kunci enkripsi setelah menyimpan router**, karena kredensial lama tidak dapat didekripsi.
- Admin awal hanya dibuat ketika tabel user masih kosong. Mengubah ADMIN_PASSWORD di .env setelah akun awal terbentuk tidak otomatis mengubah password akun.
- Siapkan backup volume/database secara terpisah dan uji pemulihannya.
- Tidak ada fitur reset password melalui email pada versi awal ini.

## Batasan versi awal

- Monitoring status pelanggan melakukan polling saat halaman pelanggan aktif; trafik historis mulai terkumpul setelah aplikasi dan router berjalan. Grafik dapat kosong sebelum ada sampel.
- Waktu riwayat adalah waktu server saat tindakan berhasil diverifikasi. Jika address-list sudah ada sebelum aplikasi mengelolanya, aplikasi tidak mengarang waktu isolasi sebelumnya.
- Riwayat saat ini fokus pada tindakan isolasi/pemulihan, belum merupakan audit log lengkap seluruh perubahan queue.
- RouterOS API dan field yang tersedia dapat berbeda berdasarkan versi, model, konfigurasi, hak akses, dan jenis queue. Validasi di lab sebelum penggunaan produksi.
- TLS API harus dikonfigurasi pada RouterOS dan sertifikatnya sesuai dengan kebijakan jaringan.

## Pengembangan lokal

~~~bash
cp .env.example .env
# Isi secret kuat; pastikan APP_ENCRYPTION_KEY berisi 64 karakter hex.
npm install
npm start
~~~

SQLite tersimpan pada direktori DATA_DIR (default ./data di luar container). Untuk development, jalankan dengan Node.js 22 atau lebih baru.


## Sinkronisasi otomatis konfigurasi MikroTik

Aplikasi memeriksa setiap router setiap **30 detik** melalui RouterOS API, membaca Simple Queue dan IPv4 Firewall Address List yang dikonfigurasi sebagai `MIKROTIK_ISOLATION_LIST` (default `blocked_ip`). Snapshot sebelumnya dan perubahan yang terdeteksi disimpan di SQLite.

Endpoint API (memerlukan login/Bearer token):
- `GET /api/sync/status` — status router, waktu sinkronisasi terakhir, daftar isolasi yang digunakan, dan ringkasan perubahan.
- `GET /api/sync/changes?limit=100` — riwayat perubahan konfigurasi yang terdeteksi.
- `POST /api/sync/run` — jalankan sinkronisasi sekarang.

Perubahan yang dapat dideteksi meliputi penambahan/penghapusan queue, perubahan nama/target/max-limit/disabled, serta penambahan/penghapusan IP pada address list isolasi. Perubahan manual melalui Winbox akan tercatat pada siklus polling berikutnya. Waktu yang dicatat adalah **waktu terdeteksi**, bukan waktu pasti perubahan dilakukan. Polling tidak dapat memastikan akun/operator yang melakukan perubahan; kolom sumber ditandai sebagai perubahan eksternal/tidak teratribusi atau aksi aplikasi yang dapat dikorelasikan dengan riwayat tindakan.

Sinkronisasi bersifat observasional: aplikasi **tidak membatalkan atau menimpa perubahan manual** pada MikroTik. Sinkronisasi pertama menjadi baseline agar konfigurasi yang sudah ada tidak dianggap sebagai perubahan baru. Pastikan akun API memiliki hak baca untuk Simple Queue dan IP Firewall Address List.

Untuk memakai list sesuai konfigurasi Anda, isi file `.env` dengan:

~~~env
MIKROTIK_ISOLATION_LIST=blocked_ip
~~~

Setelah mengubah `.env`, restart container aplikasi. Perubahan kode di GitHub belum otomatis ter-deploy ke server.
