package main

import (
    "bufio"
    "flag"
    "fmt"
    "net"
    "os"
    "regexp"
    "strings"
    "sync"
)

// ANSI escape codes for colors
const (
    Cyan   = "\033[36m"
    Green  = "\033[32m"
    Red    = "\033[31m"
    Reset  = "\033[0m"
    Bold   = "\033[1m"
    Normal = "\033[0m"
)

func printBanner() {
    fmt.Println(Cyan)
    fmt.Println("**********************************************")
    fmt.Println("* SDD SPF-DKIM-DMARC Checker @Redflare-Cyber *")
    fmt.Println("**********************************************")
    fmt.Println(Reset)
}

func main() {
    // Flags
    var endpoint string
    var list string
    var mode string
    var verbose bool
    var selectorFile string

    flag.StringVar(&endpoint, "u", "", "Single endpoint")
    flag.StringVar(&list, "l", "", "List of endpoints (file)")
    flag.StringVar(&mode, "m", "all", "Mode: spf, dkim, dmarc, all")
    flag.BoolVar(&verbose, "v", false, "Verbose output")
    flag.StringVar(&selectorFile, "s", "", "File containing DKIM selectors")
    flag.Parse()

    printBanner()

    var domains []string

    // Collect domains based on flags
    if endpoint != "" {
        domains = append(domains, sanitizeEndpoint(endpoint))
    } else if list != "" {
        // Read from file
        file, err := os.Open(list)
        if err != nil {
            fmt.Printf("Error opening file: %v\n", err)
            return
        }
        defer file.Close()
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            domains = append(domains, sanitizeEndpoint(scanner.Text()))
        }
    } else {
        // Check if data is being piped into stdin
        info, err := os.Stdin.Stat()
        if err != nil {
            fmt.Printf("Error reading stdin: %v\n", err)
            return
        }
        if info.Mode()&os.ModeCharDevice == 0 {
            // if data is being piped into stdin
            scanner := bufio.NewScanner(os.Stdin)
            for scanner.Scan() {
                domains = append(domains, sanitizeEndpoint(scanner.Text()))
            }
        } else {
            fmt.Println("Please provide an endpoint with -u, a list with -l, or pipe domains into stdin.")
            return
        }
    }

    // Load DKIM selectors
    selectors := loadSelectors(selectorFile)

    // WaitGroup for concurrency
    var wg sync.WaitGroup
    domainChan := make(chan string)

    // Start worker goroutines
    for i := 0; i < 10; i++ { // Adjust the number of workers if needed
        wg.Add(1)
        go func() {
            defer wg.Done()
            for domain := range domainChan {
                fmt.Printf("%sChecking domain: %s%s\n", Bold, domain, Normal)
                switch mode {
                case "spf":
                    checkSPF(domain, verbose)
                case "dkim":
                    checkDKIM(domain, selectors, verbose)
                case "dmarc":
                    checkDMARC(domain, verbose)
                case "all":
                    checkSPF(domain, verbose)
                    checkDKIM(domain, selectors, verbose)
                    checkDMARC(domain, verbose)
                default:
                    fmt.Println("Invalid mode. Please use: spf, dkim, dmarc, all")
                    return
                }
                fmt.Println("-------------------------------")
            }
        }()
    }

    // Send domains to workers
    for _, domain := range domains {
        domainChan <- domain
    }
    close(domainChan)

    // Wait for all workers to finish
    wg.Wait()
}

func sanitizeEndpoint(endpoint string) string {
    // Remove protocol if present
    if strings.HasPrefix(endpoint, "http://") {
        endpoint = strings.TrimPrefix(endpoint, "http://")
    } else if strings.HasPrefix(endpoint, "https://") {
        endpoint = strings.TrimPrefix(endpoint, "https://")
    }
    // Remove any trailing slashes
    endpoint = strings.TrimSuffix(endpoint, "/")
    // Extract domain if URL path is provided
    if strings.Contains(endpoint, "/") {
        parts := strings.Split(endpoint, "/")
        endpoint = parts[0]
    }
    return endpoint
}

func loadSelectors(filePath string) []string {
    // Default selectors,keep in mind that sometimes using default selectors gives FPs,rewrite the function when you have time!
    selectors := []string{
        "default", "selector1", "selector2", "mail", "smtp", "google", "amazonses", "mandrill", "sendgrid", "mailjet",
    }

    if filePath == "" {
        return selectors
    }

    file, err := os.Open(filePath)
    if err != nil {
        fmt.Printf("Error opening selector file: %v\n", err)
        return selectors
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        selector := strings.TrimSpace(scanner.Text())
        if selector != "" {
            selectors = append(selectors, selector)
        }
    }

    return selectors
}

func checkSPF(domain string, verbose bool) {
    txtRecords, err := net.LookupTXT(domain)
    if err != nil {
        if verbose {
            fmt.Printf("Error fetching TXT records for SPF: %v\n", err)
        }
        fmt.Printf("%s[SPF]%s %sNo SPF record found.%s\n", Red, Reset, Red, Reset)
        return
    }
    found := false
    spfRegex := regexp.MustCompile(`(?i)^v=spf1`)
    for _, txt := range txtRecords {
        record := strings.TrimSpace(txt)
        if verbose {
            fmt.Printf("TXT Record: %s\n", record)
        }
        if spfRegex.MatchString(record) {
            fmt.Printf("%s[SPF]%s %sSPF record found.%s\n", Green, Reset, Green, Reset)
            if verbose {
                fmt.Println(record)
            }
            found = true
            // Continue checking all records,dmarc can yield FP,run single mode to retest if needed!
        }
    }
    if !found {
        fmt.Printf("%s[SPF]%s %sNo SPF record found.%s\n", Red, Reset, Red, Reset)
    }
}

func checkDMARC(domain string, verbose bool) {
    dmarcDomain := "_dmarc." + domain
    txtRecords, err := net.LookupTXT(dmarcDomain)
    if err != nil {
        if verbose {
            fmt.Printf("Error fetching TXT records for DMARC: %v\n", err)
        }
        fmt.Printf("%s[DMARC]%s %sNo DMARC record found.%s\n", Red, Reset, Red, Reset)
        return
    }
    found := false
    dmarcRegex := regexp.MustCompile(`(?i)^v=dmarc1`)
    for _, txt := range txtRecords {
        record := strings.TrimSpace(txt)
        if verbose {
            fmt.Printf("TXT Record: %s\n", record)
        }
        if dmarcRegex.MatchString(record) {
            fmt.Printf("%s[DMARC]%s %sDMARC record found.%s\n", Green, Reset, Green, Reset)
            if verbose {
                fmt.Println(record)
            }
            found = true
            break
        }
    }
    if !found {
        fmt.Printf("%s[DMARC]%s %sNo DMARC record found.%s\n", Red, Reset, Red, Reset)
    }
}

func checkDKIM(domain string, selectors []string, verbose bool) {
    var wg sync.WaitGroup
    var mu sync.Mutex
    found := false

    for _, selector := range selectors {
        wg.Add(1)
        go func(selector string) {
            defer wg.Done()
            dkimDomain := selector + "._domainkey." + domain
            txtRecords, err := net.LookupTXT(dkimDomain)
            if err != nil {
                return
            }
            for _, txt := range txtRecords {
                record := strings.TrimSpace(txt)
                if verbose {
                    fmt.Printf("TXT Record for %s: %s\n", dkimDomain, record)
                }
                if strings.HasPrefix(strings.ToLower(record), "v=dkim1") {
                    mu.Lock()
                    if !found {
                        fmt.Printf("%s[DKIM]%s %sDKIM record found with selector '%s'.%s\n", Green, Reset, Green, selector, Reset)
                        if verbose {
                            fmt.Println(record)
                        }
                        found = true
                    }
                    mu.Unlock()
                    return
                }
            }
        }(selector)
    }

    wg.Wait()

    if !found {
        fmt.Printf("%s[DKIM]%s %sNo DKIM record found with provided selectors.%s\n", Red, Reset, Red, Reset)
    }
}

