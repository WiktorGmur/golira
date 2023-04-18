package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/happierall/l"
)

type VirusTotalResponse struct {
	Data struct {
		Id            string `json:"id"`
		Type          string `json:"type"`
		Attributes    Attributes
		Links         Links         `json:"links"`
		Relationships Relationships `json:"relationships"`
	} `json:"data"`
}

type Attributes struct {
	ASN                    int                       `json:"asn"`
	Country                string                    `json:"country"`
	LastAnalysisStats      Stats                     `json:"last_analysis_stats"`
	LastAnalysisResults    map[string]AnalysisResult `json:"last_analysis_results"`
	Reputation             int                       `json:"reputation"`
	WhoisRegisteredName    string                    `json:"whois_registered_name"`
	WhoisRegistrantEmail   string                    `json:"whois_registrant_email"`
	WhoisRegistrantName    string                    `json:"whois_registrant_name"`
	WhoisRegistrantCountry string                    `json:"whois_registrant_country"`
}

type Stats struct {
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Timeout    int `json:"timeout"`
	Failed     int `json:"failed"`
}

type AnalysisResult struct {
	Category          string `json:"category"`
	EngineName        string `json:"engine_name"`
	MethodDescription string `json:"method_description"`
	Result            string `json:"result"`
	Severity          string `json:"severity"`
}

type Links struct {
	Self string `json:"self"`
}

type Relationships struct {
	LastAnalysis Analysis `json:"last_analysis"`
}

type Analysis struct {
	Data struct {
		Id string `json:"id"`
	} `json:"data"`
}

func colorizeReputation(reputation int) string {
	if reputation >= 0 && reputation < 30 {
		return l.Colorize(strconv.Itoa(reputation), l.Red)
	} else if reputation >= 30 && reputation < 60 {
		return l.Colorize(strconv.Itoa(reputation), l.Yellow)
	} else {
		return l.Colorize(strconv.Itoa(reputation), l.Green)
	}
}

func main() {
	// Get IP from the user
	userInput := os.Args[1]

	// Make a request to the API
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", userInput)

	// Create a new HTTP request with headers
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("x-apikey", "PUT_YOUR_VIRUSTOTAL_API_KEY_HERE")
	req.Header.Add("Accept", "application/json")

	// Send HTTP request with HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// Decode API response
	var data VirusTotalResponse
	err = json.Unmarshal(body, &data)
	if err != nil {
		panic(err)
	}

	// Print output
	fmt.Printf("IP Address %v is marked as %v (Harmless: %v, Malicious: %v, Suspicious: %v, Undetected: %v)\n",
		l.Colorize(userInput, l.Blue),
		colorizeReputation(data.Data.Attributes.Reputation),
		l.Colorize(strconv.Itoa(data.Data.Attributes.LastAnalysisStats.Harmless), l.Green),
		l.Colorize(strconv.Itoa(data.Data.Attributes.LastAnalysisStats.Malicious), l.Red),
		l.Colorize(strconv.Itoa(data.Data.Attributes.LastAnalysisStats.Suspicious), l.Yellow),
		l.Colorize(strconv.Itoa(data.Data.Attributes.LastAnalysisStats.Undetected), l.White))
}
