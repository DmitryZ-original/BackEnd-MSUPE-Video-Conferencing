package main

import (
	"context"
	"database/sql"
	"fmt"

	"log"
	"net/http"

	"encoding/json"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

var db *sql.DB

// Структура для передачи данных в шаблоны
type TemplateData struct {
	ErrorMessage string
	Username     string // Будет хранить введенное имя/ФИО при регистрации
	Email        string // Будет хранить введенный email
}

const (
	dbDSN     = "postgres://postgres:admin@localhost:5432/ruscord?sslmode=disable" // ЗАМЕНИТЕ (postgres:2440894@localhost:5432/Mixa)
	dbTimeout = 5 * time.Second
)

func main() {
	var err error
	db, err = initDB(dbDSN)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	log.Println("Пул соединений с БД успешно создан.")

	fs := http.FileServer(http.Dir("../../FrontEnd-MSUPE-Video-Conferencing/srcgit/vue/dist"))
	http.Handle("/", fs) // отдаём Vue-фронтенд вместо homeHandler
	http.HandleFunc("/api/register", registerHandlerAPI)
	http.HandleFunc("/api/login", loginHandlerAPI)

	port := ":8080"
	fmt.Printf("Сервер запущен на http://localhost%s\n", port)
	err = http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("Не удалось запустить сервер: %v", err)
	}
}

func initDB(dsn string) (*sql.DB, error) {
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("ошибка открытия соединения с БД: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	err = conn.PingContext(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ошибка проверки соединения с БД (ping): %w", err)
	}
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(25)
	conn.SetConnMaxLifetime(5 * time.Minute)
	return conn, nil
}

func registerHandlerAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	if data.Username == "" || data.Email == "" || data.Password == "" {
		http.Error(w, "Все поля обязательны", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Ошибка хеширования", http.StatusInternalServerError)
		return
	}

	query := `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)`
	_, err = db.Exec(query, data.Username, data.Email, string(hashedPassword))
	if err != nil {
		http.Error(w, "Ошибка сохранения в БД", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"registered"}`))
}

func loginHandlerAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	var storedHash, username string
	query := `SELECT username, password_hash FROM users WHERE email = $1`
	err := db.QueryRow(query, creds.Email).Scan(&username, &storedHash)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Неверный пароль", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"status":"ok","username":"%s"}`, username)))
}
