package main

import (
  "crypto/tls"
  "fmt"
  "os"
  "os/exec"
  "time"
)

func checkWebsiteCertExpiration(url string) (bool, error) {
  // Perform a TLS handshake with the website
  conn, err := tls.Dial("tcp", url, &tls.Config{InsecureSkipVerify: true})
  if err != nil {
    return false, err
  }
  defer conn.Close()

  // Extract the leaf certificate from the TLS connection
  leafCert := conn.ConnectionState().PeerCertificates[0]

  // Print certificate information
  fmt.Printf("Certificate Subject: %s\n", leafCert.Subject)
  fmt.Printf("Valid From: %s\n", leafCert.NotBefore)
  fmt.Printf("Valid Until: %s\n", leafCert.NotAfter)

  // Check if the certificate is expired
  now := time.Now()
  expiration := leafCert.NotAfter
  timeUntilExpiration := expiration.Sub(now)

  // Notify if the certificate will expire soon
  if timeUntilExpiration < time.Hour {
    var message string
    if timeUntilExpiration > 0 {
      message = "will expire soon."
    } else {
      message = "expired"
    }

    fmt.Printf("Website SSL Certificate %s\n", message)
    return true, nil
  }

  fmt.Printf("Website SSL Certificate is still valid in %v.\n", timeUntilExpiration)
  return false, nil
}

func runUpdateScript(scriptPath string) error {
  // Run update script
  cmd := exec.Command(scriptPath)
  cmd.Stdin = os.Stdin
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr
  return cmd.Run()
}

func main() {
  if len(os.Args) < 3 {
    fmt.Printf("Usage: %s <website_url> <script>\n", os.Args[0])
    return
  }

  websiteURL := os.Args[1]
  updateScript := os.Args[2]

  ret, err := checkWebsiteCertExpiration(websiteURL)
  if err != nil {
    fmt.Printf("Error: %v\n", err)
    return
  }

  if ret {
    fmt.Println("Running update script")
    err := runUpdateScript(updateScript)
    if err != nil {
      fmt.Printf("Error: %v\n", err)
    }
  }
}

