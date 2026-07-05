# Tugas Keamanan Informasi - Sistem Keamanan Hibrida & Steganografi

Tugas ini berisi program simulasi untuk mengamankan pesan teks menggunakan kombinasi kriptografi dan steganografi LSB (Least Significant Bit).

## Fitur Program
* **Digital Signature (DSA):** Menandatangani pesan asli untuk memastikan data tidak diubah.
* **Diffie-Hellman (DH):** Membuat kunci bersama antara pengirim dan penerima.
* **Enkripsi AES-CBC:** Mengenkripsi pesan dan tanda tangan digital agar tidak bisa dibaca langsung.
* **Steganografi LSB:** Menyisipkan hasil enkripsi ke dalam file gambar (PNG/JPG).

---

## Cara Menjalankan

1. **Instal Library yang Dibutuhkan:**
   Buka Terminal atau CMD, lalu ketik perintah berikut:
   ```bash
   pip install pillow cryptography
2. **Jalankan program:**
   ketik perintah berikut:
   ```bash
   python TugasM11.py
