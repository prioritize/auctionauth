package auctionauth

import (
	"bytes"
	"dbconnector"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	// Hopefully the requirement for this blank import goes away
	_ "github.com/lib/pq"
)

type Token struct {
	Client       string
	Secret       string
	Token        string
	LastModified int
	LastUpdated  time.Time
}
type URL struct {
	Token string `json:"tokenrequest"`
}
type Credentials struct {
	Client string `json:"cid"`
	Secret string `json:"csecret"`
}

// NewAuthData creates a new set of tokens
func NewTokenData() (Token, bool) {
	// now := time.Now()

	url, check := GetURL()
	if !check {
		return Token{}, true
	}

	credentials, check := GetCredentials()
	if !check {
		return Token{}, true
	}

	//TODO: Consider passing this an an argument
	grantString := "grant_type=client_credentials"
	client := http.Client{Timeout: time.Second * 5}
	req, err := http.NewRequest(http.MethodPost, url.Token, bytes.NewBuffer([]byte(grantString)))

	if err != nil {
		fmt.Println("http.NewRequest failed in NewTokenData()")
		return Token{}, true
	}

	// Setup the information for the token request
	req.SetBasicAuth(credentials.Client, credentials.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Perform the POST operation
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("http.Client.Do() failed in NewTokenData()")
		return Token{}, true
	}

	// Read the body of the response
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("ReadAll failed in NewTokenData()")
		return Token{}, true
	}

	token := Token{}
	err = json.Unmarshal(body, &token)
	if err != nil {
		fmt.Println("Unmarshalling failed in NewTokenData()")
		return Token{}, true
	}
	return token, false

	// TODO -- else return data from database
}

// GetCredentials gets the credentials stored in auctionjson and returns them as a Credentials{} value
func GetCredentials() (Credentials, bool) {
	credentialFile, err := os.Open("auctionjson/credentials.json")
	if err != nil {
		return Credentials{}, true
	}

	body, err := ioutil.ReadAll(credentialFile)
	if err != nil {
		return Credentials{}, true
	}

	credentials := Credentials{}
	err = json.Unmarshal(body, &credentials)
	if err != nil {
		return Credentials{}, true
	}
	return credentials, false

}
func GetLastToken() (Token, bool) {
	// Create the DB connection to get the previous connection information
	db := dbconnector.NewDBConnection()
	statement, err := db.Prepare("SELECT * FROM auths ORDER by time DESC LIMIT 1;")
	if err != nil {
		fmt.Println("db.Prepare generated an error in GetLastToken()")
		fmt.Println(err)
		return Token{}, true
	}
	rows, err := statement.Query()
	token := Token{}
	for rows.Next() {
		//Create the location to store the data information here)
		err := rows.Scan(&token.Token, &token.LastModified, &token.LastUpdated)
		if err != nil {
			fmt.Println("Scanning from database failed in NewTokenData")
			return Token{}, true
		}
	}
	return token, false
}

// GetURL returns the URL to request a token from
func GetURL() (URL, bool) {
	jsonFile, err := os.Open("auctionjson/api.json")
	if err != nil {
		return URL{}, true
	}
	body, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return URL{}, true
	}
	url := URL{}
	err = json.Unmarshal(body, url)

	if err != nil {
		return URL{}, true
	}
	return url, false
}

//TODO: Make this prettier, determine how to set variables in string through http.Request
func CheckCurrentToken() bool {
	// Create the client to make the request
	client := http.Client{Timeout: 5 * time.Second}
	// Get the last token from the database
	token, check := GetLastToken()
	// Get the credentials, although this may not be needed
	creds, check := GetCredentials()
	if !check {
		fmt.Println("Get Credentials failed")
	}
	fmt.Println(check)
	fmt.Println(token.Token)
	url := "https://us.battle.net/oauth/check_token"
	tokenString := fmt.Sprintf("token=%s", token.Token)
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte(tokenString)))
	fmt.Println(err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(creds.Client, creds.Secret)
	res, err := client.Do(request)
	if err != nil {
		fmt.Println("client.Do() failed")
		fmt.Println(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("ReadAll failed")
	}
	fmt.Println(string(body))
	return true

}
