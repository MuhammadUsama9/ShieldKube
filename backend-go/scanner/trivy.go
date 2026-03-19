package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// RunTrivyScan executes the Trivy CLI tool against a container image locally
// and transforms its JSON vulnerability output into the expected ShieldKube schema.
func RunTrivyScan(image string) ([]map[string]interface{}, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", "--quiet", "--no-progress", image)
	out, err := cmd.Output()
	if err != nil {
		// Trivy returns non-zero exit codes if it fails entirely.
		// Sometimes it might just be the image doesn't exist.
		return nil, fmt.Errorf("trivy execution failed: %v, output: %s", err, string(out))
	}

	var trivyReport struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(out, &trivyReport); err != nil {
		return nil, err
	}

	var formattedVulns []map[string]interface{}
	for _, result := range trivyReport.Results {
		for _, v := range result.Vulnerabilities {
            // Filter noise, focus on High/Critical
            if v.Severity != "HIGH" && v.Severity != "CRITICAL" {
                continue
            }
            
            title := v.Title
            if title == "" {
                title = fmt.Sprintf("%s vulnerability in %s", v.VulnerabilityID, v.PkgName)
            }

			formattedVulns = append(formattedVulns, map[string]interface{}{
				"id":        v.VulnerabilityID,
				"severity":  capitalize(v.Severity),
				"title":     title,
				"remediation":  fmt.Sprintf("Update %s from %s to %s", v.PkgName, v.InstalledVersion, v.FixedVersion),
			})
		}
	}
	return formattedVulns, nil
}

func capitalize(s string) string {
    switch s {
    case "CRITICAL": return "Critical"
    case "HIGH": return "High"
    case "MEDIUM": return "Medium"
    case "LOW": return "Low"
    }
    return s
}
