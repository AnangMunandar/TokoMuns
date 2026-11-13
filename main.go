package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

// Penyimpanan session admin
var (
	sessions  = make(map[string]time.Time)
	sessionMu sync.Mutex
)

// Struktur data pesanan
type ItemRequest struct {
	Nama string `json:"nama"`
}

type PermintaanPesanan struct {
	Nama    string        `json:"nama"`
	Telepon string        `json:"telepon"`
	Alamat  string        `json:"alamat"`
	Item    []ItemRequest `json:"item"`
}

type ItemPesanan struct {
	Nama  string `json:"nama"`
	Harga int    `json:"harga"`
}

type Pesanan struct {
	ID      string        `json:"id"`
	Nama    string        `json:"nama"`
	Telepon string        `json:"telepon"`
	Alamat  string        `json:"alamat"`
	Item    []ItemPesanan `json:"item"`
	Total   int           `json:"total"`
	Waktu   string        `json:"waktu"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Produk struct {
	ID        int    `json:"id"`
	Nama      string `json:"nama"`
	Harga     int    `json:"harga"`
	Deskripsi string `json:"deskripsi"`
	Gambar    string `json:"gambar"`
	Stok      int    `json:"stok"`
}

// Mengirim respons JSON
func kirimJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Koneksi database SQLite
func koneksiDatabase() error {
	var err error

	db, err = sql.Open("sqlite", "toko.db")
	if err != nil {
		return err
	}

	if err = db.Ping(); err != nil {
		return err
	}

	query := `
	CREATE TABLE IF NOT EXISTS orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_code TEXT UNIQUE,
		nama TEXT NOT NULL,
		telepon TEXT NOT NULL,
		alamat TEXT NOT NULL,
		items_json TEXT NOT NULL,
		total INTEGER NOT NULL,
		created_at TEXT NOT NULL
	);
	`

	_, err = db.Exec(query)
	if err != nil {
		return err
	}

	queryProduk := `
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nama TEXT NOT NULL UNIQUE,
    harga INTEGER NOT NULL,
    deskripsi TEXT,
    gambar TEXT,
    stok INTEGER NOT NULL DEFAULT 0
);
`

	_, err = db.Exec(queryProduk)
	if err != nil {
		return err
	}

	produkAwal := []Produk{
		{
			Nama:      "Kaos Casual",
			Harga:     75000,
			Deskripsi: "Kaos casual nyaman digunakan",
			Gambar:    "",
			Stok:      20,
		},
		{
			Nama:      "Sepatu Sneakers",
			Harga:     250000,
			Deskripsi: "Sepatu sneakers untuk aktivitas sehari-hari",
			Gambar:    "",
			Stok:      10,
		},
		{
			Nama:      "Tas Backpack",
			Harga:     150000,
			Deskripsi: "Tas backpack untuk kebutuhan sehari-hari",
			Gambar:    "",
			Stok:      15,
		},
	}

	for _, p := range produkAwal {
		_, err = db.Exec(`
        INSERT OR IGNORE INTO products
        (nama, harga, deskripsi, gambar, stok)
        VALUES (?, ?, ?, ?, ?)
    `, p.Nama, p.Harga, p.Deskripsi, p.Gambar, p.Stok)

		if err != nil {
			return err
		}
	}

	return nil
}

// Membuat token session acak
func buatToken() (string, error) {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// API POST: Login admin
func adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		kirimJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"pesan": "Metode tidak diizinkan",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10*1024)
	defer r.Body.Close()

	var login LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
		kirimJSON(w, http.StatusBadRequest, map[string]string{
			"pesan": "Data login tidak valid",
		})
		return
	}

	usernameAdmin := os.Getenv("ADMIN_USERNAME")
	passwordAdmin := os.Getenv("ADMIN_PASSWORD")

	if usernameAdmin == "" || passwordAdmin == "" {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Konfigurasi admin belum tersedia",
		})
		return
	}

	userOK := subtle.ConstantTimeCompare(
		[]byte(login.Username),
		[]byte(usernameAdmin),
	)

	passOK := subtle.ConstantTimeCompare(
		[]byte(login.Password),
		[]byte(passwordAdmin),
	)

	if userOK != 1 || passOK != 1 {
		kirimJSON(w, http.StatusUnauthorized, map[string]string{
			"pesan": "Username atau password salah",
		})
		return
	}

	token, err := buatToken()
	if err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal membuat session",
		})
		return
	}

	sessionMu.Lock()
	sessions[token] = time.Now().Add(8 * time.Hour)
	sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   8 * 60 * 60,
	})

	kirimJSON(w, http.StatusOK, map[string]string{
		"pesan": "Login berhasil",
	})
}

// Middleware untuk melindungi halaman admin dan API
func wajibLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_session")

		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				kirimJSON(w, http.StatusUnauthorized, map[string]string{
					"pesan": "Silakan login terlebih dahulu",
				})
			} else {
				http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			}
			return
		}

		sessionMu.Lock()

		expiredAt, valid := sessions[cookie.Value]

		if valid && time.Now().After(expiredAt) {
			delete(sessions, cookie.Value)
			valid = false
		}

		sessionMu.Unlock()

		if !valid {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				kirimJSON(w, http.StatusUnauthorized, map[string]string{
					"pesan": "Session berakhir. Silakan login kembali",
				})
			} else {
				http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// API POST: Logout admin
func adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		kirimJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"pesan": "Metode tidak diizinkan",
		})
		return
	}

	cookie, err := r.Cookie("admin_session")

	if err == nil {
		sessionMu.Lock()
		delete(sessions, cookie.Value)
		sessionMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	kirimJSON(w, http.StatusOK, map[string]string{
		"pesan": "Logout berhasil",
	})
}

// API POST: Membuat pesanan

// API POST: Membuat pesanan
func buatPesanan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		kirimJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"pesan": "Metode tidak diizinkan",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var permintaan PermintaanPesanan

	if err := json.NewDecoder(r.Body).Decode(&permintaan); err != nil {
		kirimJSON(w, http.StatusBadRequest, map[string]string{
			"pesan": "Data tidak valid",
		})
		return
	}

	if strings.TrimSpace(permintaan.Nama) == "" ||
		strings.TrimSpace(permintaan.Telepon) == "" ||
		strings.TrimSpace(permintaan.Alamat) == "" ||
		len(permintaan.Item) == 0 {

		kirimJSON(w, http.StatusBadRequest, map[string]string{
			"pesan": "Semua data wajib diisi",
		})
		return
	}

	daftarHarga := map[string]int{
		"Kaos Casual":     75000,
		"Sepatu Sneakers": 250000,
		"Tas Backpack":    150000,
	}

	var itemPesanan []ItemPesanan
	total := 0

	for _, item := range permintaan.Item {
		namaProduk := strings.TrimSpace(item.Nama)
		harga, ditemukan := daftarHarga[namaProduk]

		if !ditemukan {
			kirimJSON(w, http.StatusBadRequest, map[string]string{
				"pesan": "Produk tidak ditemukan: " + namaProduk,
			})
			return
		}

		itemPesanan = append(itemPesanan, ItemPesanan{
			Nama:  namaProduk,
			Harga: harga,
		})

		total += harga
	}

	dataItem, err := json.Marshal(itemPesanan)
	if err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal memproses produk",
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal memulai transaksi",
		})
		return
	}
	defer tx.Rollback()

	waktu := time.Now().Format(time.RFC3339)

	// Simpan pesanan baru dengan order_code NULL.
	// NULL diperbolehkan berulang pada kolom UNIQUE SQLite.
	result, err := tx.Exec(`
		INSERT INTO orders
		(order_code, nama, telepon, alamat, items_json, total, created_at)
		VALUES (NULL, ?, ?, ?, ?, ?, ?)
	`,
		permintaan.Nama,
		permintaan.Telepon,
		permintaan.Alamat,
		string(dataItem),
		total,
		waktu,
	)

	if err != nil {
		log.Println("Gagal menyimpan pesanan:", err)
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal menyimpan pesanan",
		})
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal membuat nomor pesanan",
		})
		return
	}

	// Buat kode pesanan unik berdasarkan ID database.
	kodePesanan := fmt.Sprintf("TK%04d", id)

	_, err = tx.Exec(
		"UPDATE orders SET order_code = ? WHERE id = ?",
		kodePesanan,
		id,
	)

	if err != nil {
		log.Println("Gagal memperbarui nomor pesanan:", err)
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal memperbarui nomor pesanan",
		})
		return
	}

	if err = tx.Commit(); err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal menyelesaikan pesanan",
		})
		return
	}

	pesanan := Pesanan{
		ID:      kodePesanan,
		Nama:    permintaan.Nama,
		Telepon: permintaan.Telepon,
		Alamat:  permintaan.Alamat,
		Item:    itemPesanan,
		Total:   total,
		Waktu:   waktu,
	}

	kirimJSON(w, http.StatusCreated, pesanan)

}

// API GET: Mengambil seluruh riwayat pesanan
func daftarPesanan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		kirimJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"pesan": "Metode tidak diizinkan",
		})
		return
	}

	rows, err := db.Query(`
		SELECT order_code, nama, telepon, alamat,
		       items_json, total, created_at
		FROM orders
		ORDER BY id DESC
	`)

	if err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal mengambil data pesanan",
		})
		return
	}
	defer rows.Close()

	daftar := []Pesanan{}

	for rows.Next() {
		var p Pesanan
		var dataItem string

		err := rows.Scan(
			&p.ID,
			&p.Nama,
			&p.Telepon,
			&p.Alamat,
			&dataItem,
			&p.Total,
			&p.Waktu,
		)

		if err != nil {
			kirimJSON(w, http.StatusInternalServerError, map[string]string{
				"pesan": "Gagal membaca pesanan",
			})
			return
		}

		err = json.Unmarshal([]byte(dataItem), &p.Item)
		if err != nil {
			kirimJSON(w, http.StatusInternalServerError, map[string]string{
				"pesan": "Gagal membaca produk",
			})
			return
		}

		daftar = append(daftar, p)
	}

	if err := rows.Err(); err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Kesalahan database",
		})
		return
	}

	kirimJSON(w, http.StatusOK, daftar)
}

// API GET: Mengambil seluruh produk
func daftarProduk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		kirimJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"pesan": "Metode tidak diizinkan",
		})
		return
	}

	rows, err := db.Query(`
		SELECT id, nama, harga, deskripsi, gambar, stok
		FROM products
		ORDER BY id DESC
	`)

	if err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Gagal mengambil produk",
		})
		return
	}
	defer rows.Close()

	produk := []*Produk{}

	for rows.Next() {
		var p Produk

		err := rows.Scan(
			&p.ID,
			&p.Nama,
			&p.Harga,
			&p.Deskripsi,
			&p.Gambar,
			&p.Stok,
		)

		if err != nil {
			kirimJSON(w, http.StatusInternalServerError, map[string]string{
				"pesan": "Gagal membaca produk",
			})
			return
		}

		produk = append(produk, &p)
	}

	if err := rows.Err(); err != nil {
		kirimJSON(w, http.StatusInternalServerError, map[string]string{
			"pesan": "Kesalahan database",
		})
		return
	}

	kirimJSON(w, http.StatusOK, produk)
}

// API POST: Menambahkan produk baru
func tambahProduk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		kirimJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"pesan": "Metode tidak diizinkan",
		})
		return
	}

	var p Produk

	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		kirimJSON(w, http.StatusBadRequest, map[string]string{
			"pesan": "Format data tidak valid",
		})
		return
	}

	p.Nama = strings.TrimSpace(p.Nama)
	p.Deskripsi = strings.TrimSpace(p.Deskripsi)
	p.Gambar = strings.TrimSpace(p.Gambar)

	if p.Nama == "" || p.Harga <= 0 || p.Stok < 0 {
		kirimJSON(w, http.StatusBadRequest, map[string]string{
			"pesan": "Nama, harga, atau stok tidak valid",
		})
		return
	}

	_, err := db.Exec(`
		INSERT INTO products (nama, harga, deskripsi, gambar, stok)
		VALUES (?, ?, ?, ?, ?)
	`, p.Nama, p.Harga, p.Deskripsi, p.Gambar, p.Stok)

	if err != nil {
		kirimJSON(w, http.StatusBadRequest, map[string]string{
			"pesan": "Gagal menyimpan produk. Pastikan nama produk belum digunakan.",
		})
		return
	}

	kirimJSON(w, http.StatusCreated, map[string]string{
		"pesan": "Produk berhasil ditambahkan",
	})
}

// Program utama
func main() {
	err := koneksiDatabase()
	if err != nil {
		log.Fatal("Database gagal dibuka: ", err)
	}
	defer db.Close()

	// API pemesanan untuk pelanggan
	http.HandleFunc("/api/orders", buatPesanan)
	// API daftar produk
	http.HandleFunc("/api/products", daftarProduk)
	// API tambah produk khusus admin
	http.Handle("/api/admin/products",
		wajibLogin(http.HandlerFunc(tambahProduk)),
	)
	// API login dan logout admin
	http.HandleFunc("/api/admin/login", adminLogin)
	http.HandleFunc("/api/admin/logout", adminLogout)

	// API riwayat pesanan hanya untuk admin yang login
	http.Handle(
		"/api/orders/history",
		wajibLogin(http.HandlerFunc(daftarPesanan)),
	)

	// Halaman dashboard hanya untuk admin yang login
	http.Handle(
		"/admin.html",
		wajibLogin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/admin.html" {
				http.NotFound(w, r)
				return
			}

			http.ServeFile(w, r, "./static/admin.html")
		})),
	)

	// Halaman website dan login tetap bisa diakses publik
	http.Handle("/", http.FileServer(http.Dir("./static")))

	fmt.Println("================================")
	fmt.Println("TOKOKITA ONLINE BERJALAN")
	fmt.Println("Website: http://localhost:8080")
	fmt.Println("Login:   http://localhost:8080/login.html")
	fmt.Println("Admin:   http://localhost:8080/admin.html")
	fmt.Println("Database SQLite berhasil terhubung")
	fmt.Println("================================")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
