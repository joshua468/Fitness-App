package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var (
	db    *sql.DB
	store *sessions.CookieStore
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type Workout struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Date      time.Time `json:"date"`
	Duration  int       `json:"duration"`
	Intensity string    `json:"intensity"`
}

func init() {
	dbConn, err := sql.Open("mysql", "joshua468:Temitope2080@tcp(localhost:3306)/mydb")
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	db = dbConn

	store = sessions.NewCookieStore([]byte("secret-key"))
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/signup", signupHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")
	r.HandleFunc("/workouts", requireLogin(getWorkoutsHandler)).Methods("GET")
	r.HandleFunc("/workouts", requireLogin(addWorkoutHandler)).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", r))
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", user.Username, user.Password)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var storedUser User
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", user.Username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["user"] = storedUser.Username
	session.Save(r, w)

	w.WriteHeader(http.StatusOK)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "user")
	session.Save(r, w)
}

func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if _, ok := session.Values["user"]; !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func getWorkoutsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	username := session.Values["user"].(string)

	rows, err := db.Query("SELECT id, user_id, date, duration, intensity FROM workouts WHERE username = ?", username)
	if err != nil {
		http.Error(w, "Error fetching workouts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	workouts := make([]Workout, 0)
	for rows.Next() {
		var workout Workout
		if err := rows.Scan(&workout.ID, &workout.UserID, &workout.Date, &workout.Duration, &workout.Intensity); err != nil {
			http.Error(w, "Error scanning workouts", http.StatusInternalServerError)
			return
		}
		workouts = append(workouts, workout)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(workouts)
}

func addWorkoutHandler(w http.ResponseWriter, r *http.Request) {
	var workout Workout
	if err := json.NewDecoder(r.Body).Decode(&workout); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "session")
	username := session.Values["user"].(string)

	_, err := db.Exec("INSERT INTO workouts(user_id, date, duration, intensity) VALUES(?, ?, ?, ?)", workout.UserID, workout.Date, workout.Duration, workout.Intensity)
	if err != nil {
		http.Error(w, "Error adding workout", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
