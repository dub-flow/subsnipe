package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	_ "embed"

	"github.com/fatih/color"
	"github.com/hashicorp/go-version"
)

//go:embed VERSION
var AppVersion string
var latestRelease = "https://github.com/dub-flow/subsnipe/releases/latest"

func NotifyOfUpdates() {
	client := &http.Client{}
	req, err := http.NewRequest("GET", latestRelease, nil)
	if err != nil {
		return
	}

	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var response map[string]interface{}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return
	}

	vCurrent, err := version.NewVersion(AppVersion)
	if err != nil {
		fmt.Print(err)
	}

	vLatest, err := version.NewVersion(response["tag_name"].(string))
	if err != nil {
		fmt.Print(err)
	}

	// check if a newer version exists in the GitHub Releases
	if vCurrent.LessThan(vLatest) {
		color.Red(fmt.Sprintf("Please upgrade to the latest version of this tool (%s) by visiting %s\n\n", response["tag_name"], latestRelease))
	}
}

func printAppVersion() {
	// this should never happen, since we embed the version inside the
	// application.
	if AppVersion == "" {
		AppVersion = "0.0.0-unknown"
	}

	color.Yellow("Current version: %s\n\n", AppVersion)
}
