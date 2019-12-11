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

// Token stores all the data required for a token
type Token struct {
	Client       string
	Secret       string
	Token        string `json:"access_token"`
	LastModified int
	LastUpdated  time.Time
}

// TokenURL stores a string with the `json:"tokenrequest"` property
type TokenURL struct {
	URL string `json:"tokenrequest"`
}

// CheckTokenURL stores a string with the `json:"tokencheck"` property
type CheckTokenURL struct {
	URL string `json:"tokencheck"`
}

// Credentials stores the values to pass to the api for authentication
type Credentials struct {
	Client string `json:"cid"`
	Secret string `json:"csecret"`
}

// CheckResponse is used to store the response of a check_token api call
type CheckResponse struct {
	Expires  int    `json:"exp"`
	UserName string `json:"user_name"`
	// Authorities []string `json:"authorities"`
	Client    string   `json:"user_id"`
	Scope     []string `json:"scope"`
	Error     string   `json:"error"`
	ErrorDesc string   `json:"error_description"`
}

// NewTokenData creates a new set of tokens
func NewTokenData() (Token, bool) {
	// If the last token is still valid,
	validToken, check := CheckCurrentToken()
	if !check && validToken {
		out, check := GetLastToken()
		if !check {
			return out, false
		}
	}
	token, check := GetNewToken()
	if check {
		return Token{}, true
	}
	db := dbconnector.NewDBConnection()
	_, err := db.Exec("INSERT into auths(token, lastModified, time) values($1, $2, NOW())", token.Token, 1)
	if err != nil {
		fmt.Println(err)
	}
	return token, false
	// TODO -- else return data from database
}

// GetCredentials gets the credentials stored in auctionjson and returns them as a Credentials{} value
func GetCredentials() (Credentials, bool) {
	credentialFile, err := os.Open("../auctionjson/credentials.json")
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

// GetLastToken gets the last token returned by the database
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
	if err != nil {
		fmt.Println("Error in statement.Query()")
		return Token{}, true
	}
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

// GetTokenURL returns the URL to request a token from
func GetTokenURL() (TokenURL, bool) {
	jsonFile, err := os.Open("../auctionjson/api.json")
	if err != nil {
		fmt.Println("GetTokenURL() failed to open JSON")
		return TokenURL{}, true
	}
	body, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("GetTokenURL() failed to parse JSON")
		return TokenURL{}, true
	}
	url := TokenURL{}
	err = json.Unmarshal(body, &url)
	if err != nil {
		fmt.Println("GetTokenURL failed to load JSON into struct")
		return TokenURL{}, true
	}
	return url, false
}

// GetCheckTokenURL returns the URL to verify token status
func GetCheckTokenURL() (CheckTokenURL, bool) {
	jsonFile, err := os.Open("../auctionjson/api.json")
	if err != nil {
		return CheckTokenURL{}, true
	}
	body, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return CheckTokenURL{}, true
	}
	url := CheckTokenURL{}
	err = json.Unmarshal(body, &url)

	if err != nil {
		return CheckTokenURL{}, true
	}
	return url, false
}

// CheckCurrentToken queries to api to determine if the currently held token is valid
func CheckCurrentToken() (bool, bool) {
	//TODO: Make this prettier, determine how to set variables in string through http.Request
	// url := "https://us.battle.net/oauth/check_token"
	url, check := GetCheckTokenURL()
	if check {
		fmt.Println("CheckCurrentToken() failed in GetCheckTokenURL()")
		return false, true
	}
	// Create the client to make the request
	client := http.Client{Timeout: 5 * time.Second}
	// Get the last token from the database
	token, check := GetLastToken()
	if check {
		fmt.Println("CheckCurrentToken() failed in GetLastToken()")
		return false, true
	}
	// Get the credentials, although this may not be needed
	creds, check := GetCredentials()
	if check {
		fmt.Println("CheckCurrentToken() failed in GetCredentials()")
		return false, true
	}
	// Build the string to send to the api
	tokenString := fmt.Sprintf("token=%s", token.Token)
	request, err := http.NewRequest(http.MethodPost, url.URL, bytes.NewBuffer([]byte(tokenString)))
	if err != nil {
		fmt.Println("CheckCurrentToken() failed using http.NewRequest()")
		return false, true
	}
	// Se the header to the proper data type
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// !! Not sure if this is required, but currently leaving it in place
	request.SetBasicAuth(creds.Client, creds.Secret)
	// Perform the POST
	res, err := client.Do(request)
	if err != nil {
		fmt.Println("CheckCurrentToken() failed using client.Do()")
		fmt.Println(err)
		return false, true
	}
	defer res.Body.Close()
	// Read the data returned
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("CheckCurrentToken() failed using ioutil.Readall")
		return false, true
	}
	response := CheckResponse{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("CheckCurrentToken() failed using json.Unmarshal")
		fmt.Println(string(body))
		return false, true
	}
	if response.Error == "" {
		return true, false
	}
	return false, false

}

// GetNewToken gets a new Token from the api
func GetNewToken() (Token, bool) {
	creds, check := GetCredentials()
	if check {
		return Token{}, true
	}
	url, check := GetTokenURL()
	if check {
		return Token{}, true
	}
	client := http.Client{Timeout: 10 * time.Second}
	grantString := "grant_type=client_credentials"
	request, err := http.NewRequest(http.MethodPost, url.URL, bytes.NewBuffer([]byte(grantString)))
	if err != nil {
		fmt.Println("GetNewToken() error using http.NewRequest()")
		return Token{}, true
	}
	request.SetBasicAuth(creds.Client, creds.Secret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(request)
	if err != nil {
		fmt.Println("GetNewToken() error using http.Client.Do()")
		return Token{}, true
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("GetNewToken() error using ioutil.ReadAll()")
		return Token{}, true
	}

	token := Token{}
	err = json.Unmarshal(body, &token)
	if err != nil {
		fmt.Println("GetNewToken() error using json.Unmarshal()")
		return Token{}, true
	}
	token.Client = creds.Client
	token.Secret = creds.Secret
	return token, false
}
