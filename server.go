package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

const contentSecurityPolicyValue = "default-src none;"
const contentSecurityPolicy = "Content-Security-Policy"

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("mysql", os.Getenv("database")+":"+os.Getenv("pass")+"@(remotemysql.com:3306)/"+os.Getenv("database"))
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(time.Second * 10)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	http.HandleFunc("/verify", checkHandler)
	http.HandleFunc("/create", createHandler)
	http.HandleFunc("/truncate", truncHandler)
	port := os.Getenv("PORT")
	if port == "" {
		if err := http.ListenAndServe("localhost:8080", nil); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			log.Fatal(err)
		}
	}
}

func truncHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	_, err := db.Exec("TRUNCATE TABLE users")
	if err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "Uh, that didn't work so well")
		return
	}
	fmt.Fprintf(w, "Success")
}

func createHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	email := r.FormValue("email")
	pass := r.FormValue("pass")
	if email == "" || pass == "" {
		fmt.Fprintf(w, "No input")
		return
	}
	if db == nil {
		fmt.Println("Error: At db nil, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}

	rows, err := db.Query("SELECT email FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		fmt.Fprintf(w, "Email already exists")
		return
	}

	// user does not exist, we can create one!

	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		fmt.Println("At GenerateFromPassword, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	verification, err := generateRandomString(6)
	if err != nil {
		log.Println(err)
		fmt.Println("At generateRandomString, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
	}
	fmt.Println(string(hash))
	fmt.Println(verification)

	from := "noreply.fbla.app@gmail.com"
	auth := smtp.PlainAuth("", from, os.Getenv("emailPass"), "smtp.gmail.com")
	message := []byte("Your validation code is: " + verification)
	err = smtp.SendMail("smtp.gmail.com:587", auth, from, []string{email}, message)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At SendMail, createHandler")
		fmt.Fprintf(w, "Invalid email")
		return
	}
	_, err = db.Exec(`INSERT INTO users (email, password, verification, firstName, lastName, chapter) VALUES (?, ?, ?, '', '', '')`, email, string(hash), verification)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Exec, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	fmt.Fprintf(w, "Success!")
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	if db == nil {
		fmt.Println("Error: At db nil, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	email := r.FormValue("email")
	pass := r.FormValue("pass")
	if email == "" || pass == "" {
		fmt.Fprintf(w, "No input")
		return
	}

	var hash []byte
	rows, err := db.Query("SELECT password FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&hash)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}
	}
	if hash == nil {
		fmt.Fprintf(w, "Error: incorrect password or username")
		return
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if err != nil {
		fmt.Fprintf(w, "Error: incorrect password or username")
		return
	}
	// var (
	// 	name string
	// )
	// defer rows.Close()
	// for rows.Next() {
	// 	err := rows.Scan(&name)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// 	log.Println(name)
	// }
	fmt.Fprintf(w, "Success!")
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b)[:n], nil
}

// func getUserInfo(email string) (theUser user, err error) {
// 	readDir()
// 	return
// }
//
// func readDir() {
// 	dirname := "users"
//
// 	f, err := os.Open(dirname)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	files, err := f.Readdir(-1)
// 	f.Close()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	for _, file := range files {
// 		fmt.Println(file.Name())
// 	}
// }
//
// func setUserInfo(theUser user) (err error) {
// 	dirname := "users"
//
// 	f, err := os.Open(dirname)
// 	if err != nil {
// 		return
// 	}
// 	files, err := ioutil.ReadDir(dirname)
// 	f.Close()
// 	if err != nil {
// 		return
// 	}
// 	for {
// 		var numFiles int
// 		var theFile string
// 		for _, file := range files {
// 			if file.Name() != ".DS_Store" {
// 				numFiles++
// 			}
// 			fmt.Println(file.Name()[:len(file.Name())-4])
// 		}
// 		if numFiles < 2 {
// 			_, err = os.Stat(dirname + "/" + theUser.email + ".txt")
// 			if os.IsNotExist(err) {
// 				_, err = os.Create(dirname + "/" + theUser.email + ".txt")
// 				return
// 			}
// 			return fileAlreadyExistsError()
// 		}
// 		for _, file := range files {
// 			if file.Name() == ".DS_Store" {
// 				continue
// 			}
// 			if theUser.email == file.Name()[:len(file.Name())-4] {
// 				fmt.Println(false)
// 				return
// 			}
// 			if theUser.email < file.Name()[:len(file.Name())-4] {
// 				theFile = file.Name()
// 				fmt.Println("huh")
// 				break
// 			}
// 		}
// 		dirname += theFile
// 	}
// 	//if theUser.email
// 	// userInfo, err := os.OpenFile("users/userInformation.txt", os.O_RDWR, os.ModeAppend)
// 	// defer userInfo.Close()
// 	// if err != nil {
// 	// 	return err
// 	// }
// 	// userInfo.Seek(10, 0)
// 	// userInfo.WriteAt([]byte("Golang work please"), 5)
// 	// stat, err := userInfo.Stat()
// 	// if err != nil {
// 	// 	return err
// 	// }
// 	// b := make([]byte, 1)
// 	// size := stat.Size()
// 	// var word string
// 	// var upperLimit, lowerLimit, currentLine int64 = size / charsPerLine, 0, size / (2 * charsPerLine)
// 	// userInfo.Seek(charsPerLine*currentLine, 0)
// 	// for {
// 	// 	amount, err := userInfo.Read(b)
// 	// 	if err != nil {
// 	// 		fmt.Println(err)
// 	// 		break
// 	// 	}
// 	// 	if string(b[:amount]) == " " {
// 	// 		if word == theUser.email {
// 	// 			word = ""
// 	// 			for {
// 	// 				amount, err = userInfo.Read(b)
// 	// 				if str := string(b[:amount]); err != nil || str == "\n" {
// 	// 					//a := strings.Split(word, " ")
// 	// 					fmt.Println(true)
// 	// 					break
// 	// 				} else {
// 	// 					word += str
// 	// 				}
// 	// 			}
// 	// 			break
// 	// 		} else if word < theUser.email {
// 	// 			upperLimit = currentLine
// 	// 		} else if word > theUser.email {
// 	// 			lowerLimit = currentLine
// 	// 		}
// 	// 		currentLine = (upperLimit + lowerLimit) / 2
// 	// 		// if upperLimit == currentLine || lowerLimit == currentLine {
// 	// 		// 	// TODO: Insert data
// 	// 		// 	break
// 	// 		// }
// 	// 		userInfo.Seek(currentLine*charsPerLine, 0)
// 	// 		word = ""
// 	// 	} else {
// 	// 		word += string(b[:amount])
// 	// 	}
// 	// }
// }

type user struct {
	passHash  string
	firstName string
	lastName  string
	email     string
	chapter   chapter
	roles     string
	isLeader  bool
}

type chapter struct {
	id   int
	name string
}

//
// func fileAlreadyExistsError() error {
// 	return &fileAlreadyExists{"File already exists"}
// }
//
// type fileAlreadyExists struct {
// 	s string
// }
//
// func (e *fileAlreadyExists) Error() string {
// 	return e.s
// }
