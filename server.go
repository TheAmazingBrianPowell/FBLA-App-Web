package main

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	gomail "gopkg.in/mail.v2"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var table = [10]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

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

	http.HandleFunc("/getMessages", getMessagesHandler)
	http.HandleFunc("/sendMessage", sendHandler)
	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/create", createHandler)
	http.HandleFunc("/check", checkHandler)
	http.HandleFunc("/truncate", truncHandler)
	http.HandleFunc("/createChapter", createChapterHandler)
	http.HandleFunc("/joinChapter", joinChapterHandler)
	http.HandleFunc("/report", reportHandler)
	port := os.Getenv("PORT")
	if port == "" {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			log.Fatal(err)
		}
	}
}

func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	
	email := r.FormValue("email")
	pass := r.FormValue("pass")
	user := r.FormValue("user")

	if db == nil {
		fmt.Println("Error: At db nil, reportHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}

	if email == "" || pass == "" || user == "" {
		fmt.Fprintf(w, "Invalid input")
		return
	}

	var (
		hash         []byte
		verification string
	)
	rows, err := db.Query("SELECT password, verification FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, getMessageHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&hash, &verification)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, getMessageHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}

	}
	if hash == nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}
	if verification != "" {
		fmt.Fprintf(w, "Verification error")
		return
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if err != nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}

	var (
		content string
		author string
		outString string
	)
	rows, err = db.Query("SELECT content, author FROM messages WHERE (author = ? AND recipient = ?) OR (author = ? AND recipient = ?) ORDER BY time ASC", email, user, user, email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, getMessageHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&content, &author)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}
		outString += author + "," + content + ","
	}
	if outString != "" {
		fmt.Fprintf(w, "S" + outString[:len(outString)-1])
	} else {
		fmt.Fprintf(w, "S")
	}
}

func sendHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	
	content := r.FormValue("content")
	sender := r.FormValue("sender")
	pass := r.FormValue("pass")
	recipient := r.FormValue("recipient")
	date := r.FormValue("date")
	

	if db == nil {
		fmt.Println("Error: At db nil, reportHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}

	if sender == "" || pass == "" || content == "" || recipient == "" || date == "" {
		fmt.Fprintf(w, "Invalid input")
		return
	}

	var (
		hash         []byte
		verification string
	)
	rows, err := db.Query("SELECT password, verification FROM users WHERE email = ?", sender)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&hash, &verification)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}

	}
	if hash == nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}
	if verification != "" {
		fmt.Fprintf(w, "Verification error")
		return
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if err != nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}

    _, err = db.Exec(`INSERT INTO messages (content, author, recipient, time) VALUES (?, ?, ?, ?)`, content, sender, recipient, date)
	if err != nil {
		fmt.Fprintf(w, "An unexpected error occurred")
		fmt.Println(err)
		fmt.Println("At Update, createChapterHandler")
		return
	}

	if err != nil {
		fmt.Fprintf(w, "An unexpected error occurred")
		fmt.Println(err)
		fmt.Println("At Update, createChapterHandler")
		return
	}

	fmt.Fprintf(w, "Success!")

}



func reportHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	
	message := r.FormValue("message")

	if db == nil {
		fmt.Println("Error: At db nil, reportHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}

	if message == "" {
		fmt.Fprintf(w, "Invalid input")
		return
	}

	_, err := db.Exec(`INSERT INTO bugs (message) VALUES (?)`, message)
	if err != nil {
		fmt.Fprintf(w, "An unexpected error occurred")
		fmt.Println(err)
		fmt.Println("At Update, createChapterHandler")
		return
	}

	fmt.Fprintf(w, "Success!")
}

func createChapterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	email := r.FormValue("email")
	pass := r.FormValue("pass")
	chapterName := r.FormValue("chapterName")

	if db == nil {
		fmt.Println("Error: At db nil, createChapterHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}

	if email == "" || pass == "" || chapterName == "" {
		fmt.Fprintf(w, "Invalid input")
		return
	}

	var (
		hash         []byte
		verification string
	)
	rows, err := db.Query("SELECT password, verification FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&hash, &verification)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}

	}
	if hash == nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}
	if verification != "" {
		fmt.Fprintf(w, "Verification error")
		return
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if err != nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}

	// generate random chapter code
	chapterCode, err := generateVerification(10)
	if err != nil {
		log.Println(err)
		fmt.Println("At generateRandomString, createChapterHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	_, err = db.Exec(`INSERT INTO chapters (id, name) VALUES (?, ?)`, chapterCode, chapterName)
	
	if err != nil {
		fmt.Fprintf(w, "An unexpected error occurred")
		fmt.Println(err)
		fmt.Println("At Insert, createChapterHandler")
		return
	}
	_, err = db.Exec(`UPDATE users SET chapter = ? WHERE email = ?`, chapterCode, email)
	if err != nil {
		fmt.Fprintf(w, "An unexpected error occurred")
		fmt.Println(err)
		fmt.Println("At Update, createChapterHandler")
		return
	}


	fmt.Fprintf(w, "Success!")

}

func joinChapterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	email := r.FormValue("email")
	pass := r.FormValue("pass")
	chapterCode := r.FormValue("chapterCode")

	if db == nil {
		fmt.Println("Error: At db nil, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}

	if email == "" || pass == "" || chapterCode == "" {
		fmt.Fprintf(w, "Invalid input")
		return
	}

	var (
		hash         []byte
		verification string
		name		 string
	)
	rows, err := db.Query("SELECT password, verification, name FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, joinHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&hash, &verification, &name)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}

	}
	if hash == nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}
	if verification != "" {
		fmt.Fprintf(w, "Verification error")
		return
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if err != nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}


	var chapterName string
	rows, err = db.Query("SELECT name FROM chapters WHERE id = ?", chapterCode)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&chapterName)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}

	}

	if chapterName == "" {
		fmt.Fprintf(w, "There are no chapters with this code")
		return
	}

	_, err = db.Exec(`UPDATE users SET chapter = ? WHERE email = ?`, chapterCode, email)
	if err != nil {
		fmt.Fprintf(w, "An unexpected error occurred")
		fmt.Println(err)
		fmt.Println("At Update, createChapterHandler")
		return
	}

		var (
		name2 string
		email2 string
	)
	rows, err = db.Query("SELECT name, email FROM users WHERE chapter = ?", chapterCode)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	var outText = name
	for rows.Next() {
		err := rows.Scan(&name2, &email2)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}
		if name != name2 {
			outText += "," + name2 + "," + email2
		}

	}
	fmt.Fprintf(w, "S" + outText)

}


// for testing purposes only, this function would not be in the final production
func truncHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	_, err := db.Exec("TRUNCATE TABLE users")

	if err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "Error truncating table users")
		return
	}
	_, err = db.Exec("TRUNCATE TABLE chapters")

	if err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "Error truncating table chapters")
		return
	}
	fmt.Fprintf(w, "Success")
}

func createHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	email := r.FormValue("email")
	pass := r.FormValue("pass")
    isAdvisor := r.FormValue("isAdvisor")
	if email == "" || pass == "" || isAdvisor == "" {
		fmt.Fprintf(w, "Invalid input")
		return
	}
	if db == nil {
		fmt.Println("Error: At db nil, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	var (
		verify string
		exists = false
	)
	rows, err := db.Query("SELECT verification FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	name := r.FormValue("name")
	for rows.Next() {
		rows.Scan(&verify)
		if verify != "" {
			exists = true
			break
		}
		fmt.Fprintf(w, "Email already exists")
		return
	}
	if name == "" {
		fmt.Fprintf(w, "Invalid input")
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
	verification, err := generateVerification(6)
	if err != nil {
		log.Println(err)
		fmt.Println("At generateRandomString, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
	}

	m := gomail.NewMessage()
	m.SetAddressHeader("From", "noreply.fbla.app@gmail.com", "FBLA App")
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Verify your account!")
	m.SetBody("text/html", "<!DOCTYPE html><html><head></head><body><h1>Greetings "+name+",</h1> <p>Your verification code is: "+verification+"</p><body></html>")
	d := gomail.NewDialer("smtp.gmail.com", 587, "noreply.fbla.app@gmail.com", os.Getenv("emailPass"))
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err = d.DialAndSend(m); err != nil {
		fmt.Println(err)
		fmt.Println("At SendMail, createHandler")
		fmt.Fprintf(w, "Invalid email")
		return
	}
	if exists {
		_, err = db.Exec(`UPDATE users SET password = ?, isAdvisor = ?, verification = ?, name = ? WHERE email = ?`, string(hash), isAdvisor, verification, name, email)
	} else {
		_, err = db.Exec(`INSERT INTO users (email, password, isAdvisor, verification, name, chapter) VALUES (?, ?, ?, ?, ?, '')`, email, string(hash), isAdvisor, verification, name)
	}
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Exec, createHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	fmt.Fprintf(w, "Success!")
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, contentSecurityPolicyValue)
	if db == nil {
		fmt.Println("Error: At db nil, verifyHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	email := r.FormValue("email")
	pass := r.FormValue("pass")
	verification := r.FormValue("verify")
	if email == "" || pass == "" || verification == "" {
		fmt.Fprintf(w, "Invalid input")
		return
	}
	var (
		hash          []byte
		verification2 string
	)

	rows, err := db.Query("SELECT password, verification FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, verifyHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&hash, &verification2)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, verifyHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}

	}
	if hash == nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if err != nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}
	if verification != verification2 {
		fmt.Fprintf(w, "Incorrect verification code")
		return
	}

	_, err = db.Exec("UPDATE users SET verification = ? WHERE email = ?", "", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Exec, verifyHandler")
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
		fmt.Fprintf(w, "Invalid input")
		return
	}

	var (
		hash         []byte
		verification string
		name string
		chapter string
	)
	rows, err := db.Query("SELECT password, verification, name, chapter FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&hash, &verification, &name, &chapter)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}

	}
	if hash == nil {
		fmt.Fprintf(w, "Incorrect password or username")
		return
	}
	if verification != "" {
		fmt.Fprintf(w, "Verification error")
		return
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if err != nil {
		fmt.Fprintf(w, "Incorrect password or username")
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

	var (
		name2 string
		email2 string
	)
	rows, err = db.Query("SELECT name, email FROM users WHERE chapter = ?", chapter)
	if err != nil {
		fmt.Println(err)
		fmt.Println("At Query, checkHandler")
		fmt.Fprintf(w, "An unexpected error occurred")
		return
	}
	defer rows.Close()
	var outText = name
	for rows.Next() {
		err := rows.Scan(&name2, &email2)
		if err != nil {
			fmt.Println(err)
			fmt.Println("At Scan, checkHandler")
			fmt.Fprintf(w, "An unexpected error occurred")
			return
		}
		if name != name2 {
			outText += "," + name2 + "," + email2
		}

	}
	fmt.Fprintf(w, "S" + outText)
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:n], nil
}

func generateVerification(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	fmt.Println(string(b))
	return string(b)[:length], err
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
