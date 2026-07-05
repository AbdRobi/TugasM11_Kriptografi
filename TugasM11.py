import os
import tkinter as tk
from tkinter import filedialog
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import dh, dsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


print("=== SISTEM KEAMANAN HIBRIDA + STEGANORAFi ===")
input_pesan = input("Masukkan pesan rahasia yang ingin dikirim: ")
pesan_bytes = input_pesan.encode('utf-8')

# Input nama file gambar cover menggunakan dialog
print("Silakan pilih file gambar cover dari folder...")
root = tk.Tk()
root.withdraw() # Sembunyikan window utama tkinter
root.attributes('-topmost', True) # Pastikan dialog muncul di depan
nama_gambar_cover = filedialog.askopenfilename(
    title="Pilih Gambar Cover",
    filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")]
)

if not nama_gambar_cover:
    print("Tidak ada file yang dipilih. Menggunakan nama default 'cover.png'")
    nama_gambar_cover = "cover.png"
else:
    print(f"File dipilih: {nama_gambar_cover}")

# Validasi sederhana untuk memastikan gambar dummy tersedia jika belum ada
if not os.path.exists(nama_gambar_cover):
    print(f"⚠️ File '{nama_gambar_cover}' tidak ditemukan. Membuat gambar dummy otomatis...")
    cover_image = Image.new('RGB', (300, 300), color=(50, 120, 200))
    cover_image.save(nama_gambar_cover)

print("\n" + "="*50 + "\n")

# 1. Diffie-Hellman
parameters = dh.generate_parameters(generator=2, key_size=512)
alice_dh_private = parameters.generate_private_key()
bob_dh_private = parameters.generate_private_key()

alice_dh_public = alice_dh_private.public_key()
bob_dh_public = bob_dh_private.public_key()

# 2. Pasangan Kunci DSA Alice untuk Tanda Tangan Digital
dsa_private_key = dsa.generate_private_key(key_size=1024)
dsa_public_key = dsa_private_key.public_key()

def embed_lsb(image_path, data, output_path):
    img = Image.open(image_path)
    binary_data = ''.join(format(byte, '08b') for byte in data)
    binary_data += '0000000000000000'  # 16-bit Stop Marker
    
    pixels = list(img.getdata())
    new_pixels = []
    data_idx = 0
    
    for pixel in pixels:
        new_pixel = list(pixel)
        for i in range(3):  # R, G, B channels
            if data_idx < len(binary_data):
                new_pixel[i] = (new_pixel[i] & ~1) | int(binary_data[data_idx])
                data_idx += 1
        new_pixels.append(tuple(new_pixel))
        
    img.putdata(new_pixels)
    img.save(output_path)

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    
    binary_bits = ""
    for pixel in pixels:
        for i in range(3):
            binary_bits += str(pixel[i] & 1)
            
    extracted_bytes = bytearray()
    for i in range(0, len(binary_bits), 8):
        byte_str = binary_bits[i:i+8]
        if len(byte_str) < 8: break
        byte_val = int(byte_str, 2)
        
        if len(extracted_bytes) >= 2 and extracted_bytes[-1] == 0 and byte_val == 0:
            extracted_bytes.pop()
            break
        extracted_bytes.append(byte_val)
        
    return bytes(extracted_bytes)

def proses_pengirim(pesan, cover_path, output_stego_path):
    print("[PENGIRIM] Menandatangani pesan dengan DSA...")
    signature = dsa_private_key.sign(pesan, hashes.SHA256())
    
    # Gabungkan pesan asli dan signature dengan separator '||'
    payload = pesan + b'||' + signature
    
    print("[PENGIRIM] Menghitung Kunci Bersama (Diffie-Hellman)...")
    shared_secret = alice_dh_private.exchange(bob_dh_public)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hybrid-stego',
    ).derive(shared_secret)
    
    print("[PENGIRIM] Mengenkripsi payload dengan AES-CBC...")
    iv = os.urandom(16)
    pad_len = 16 - (len(payload) % 16)
    payload_padded = payload + bytes([pad_len] * pad_len)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(payload_padded) + encryptor.finalize()
    
    paket_kirim = iv + ciphertext
    
    print(f"[PENGIRIM] Menyisipkan ciphertext ({len(paket_kirim)} bytes) ke {cover_path}...")
    embed_lsb(cover_path, paket_kirim, output_stego_path)
    print(f"🎉 [PENGIRIM] Selesai! Gambar hasil steganografi disimpan sebagai: {output_stego_path}\n")

def proses_penerima(stego_path):
    print("[PENERIMA] Mengekstrak bit data dari gambar stego...")
    paket_ekstrak = extract_lsb(stego_path)
    
    iv_dec = paket_ekstrak[:16]
    ciphertext_dec = paket_ekstrak[16:]
    
    print("[PENERIMA] Menghitung Kunci Bersama (Diffie-Hellman)...")
    shared_secret_bob = bob_dh_private.exchange(alice_dh_public)
    aes_key_bob = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hybrid-stego',
    ).derive(shared_secret_bob)
    
    print("[PENERIMA] Mendekripsi ciphertext dengan AES...")
    cipher_dec = Cipher(algorithms.AES(aes_key_bob), modes.CBC(iv_dec))
    decryptor = cipher_dec.decryptor()
    decrypted_padded = decryptor.update(ciphertext_dec) + decryptor.finalize()
    
    # Remove padding
    pad_len = decrypted_padded[-1]
    payload_dec = decrypted_padded[:-pad_len]
    
    # Memisahkan kembali pesan asli dan signature
    pesan_asli_dec, sig_dec = payload_dec.split(b'||', 1)
    
    print(f"🔓 [PENERIMA] Pesan berhasil didekripsi: {pesan_asli_dec.decode('utf-8')}")
    
    print("[PENERIMA] Memverifikasi tanda tangan digital (DSA + SHA256)...")
    try:
        dsa_public_key.verify(sig_dec, pesan_asli_dec, hashes.SHA256())
        print("✅ [PENERIMA] VERIFIKASI SUKSES: Pesan otentik dan tidak dimodifikasi!")
    except Exception:
        print("❌ [PENERIMA] VERIFIKASI GAGAL: Pesan terindikasi palsu atau rusak.")

file_stego = "stego_output.png"

# Jalankan sisi pengirim
proses_pengirim(pesan_bytes, nama_gambar_cover, file_stego)

print("-" * 50)

# Jalankan sisi penerima
proses_penerima(file_stego)