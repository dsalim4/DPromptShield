# Mulai di sini — DPromptShield AI Builder Cup

1. Baca `SUBMISSION_NOTES.md` untuk pitch dan alur demo.
2. Source backend ada di `dpromptshield_server_v1.0.4/`; extension ada di `dpromptshield_extension_v1.0.4/`.
3. Salin `.env.example` menjadi `.env` di folder server. Isi koneksi SQL Server dan Gemini API key. Jangan commit `.env`.
4. Pastikan SQL Server dapat diakses dan jalankan `npm ci`, `npm run check`, `npm start`.
5. Login ke console menggunakan admin yang sudah ada. Jika database admin masih kosong, atur `INITIAL_SUPERADMIN_PASSWORD` dan `INITIAL_ADMIN_PASSWORD` (minimal 12 karakter) melalui environment/Secret Manager.
6. Untuk extension, deploy backend dulu, lalu ganti `REPLACE_WITH_CLOUD_RUN_HOST` di `background.js` dan `content.js` dengan hostname Cloud Run sebenarnya. Load unpacked extension dari folder tersebut.
7. Buka `/ai-lab.html` untuk demo Gemini dan Firestore. Gunakan data sintetis saja.
8. Ikuti checklist dan script video di `SUBMISSION_NOTES.md`.

**Penting:** Paket ini belum memiliki URL Cloud Run/GitHub karena deployment memerlukan akses project GCP, koneksi SQL Server, Secret Manager, dan kredensial tim. URL tidak boleh direkayasa.
