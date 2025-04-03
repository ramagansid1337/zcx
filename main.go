package main

import (
    // "bytes" // Unused import
    "crypto/tls"
    "encoding/json"
    "fmt"
    // "io/ioutil" // Unused import
    "math/rand"
    "net"
    "net/http"
    "os"
    "sort"
    "strings"
    "sync"
    // "sync/atomic" // Removed unused import
    "time"
    "io"
    "encoding/base64"
    // "net/url" // Removing unused import
    
    "github.com/valyala/fasthttp"
    // "github.com/fasthttp/websocket" // Removed unused import
)

// Constants
const (
    DOMAIN = "vx.zerostresser.ru"
    BYPASS_TOKEN = "x9K#mP2$vL8nQ4@jR5"
    COOKIE_NAME = "dstat_challenge"
    COOKIE_LIFETIME = 24 * time.Hour
    MAX_HANDSHAKES_PER_IP = 5  // Reduced maximum handshakes per IP per second
    HANDSHAKE_BAN_TIME = 10 * time.Minute // Increased ban time for excessive handshakes
)

// Commenting out unused protection mechanisms
// JA3Protection      *JA3Fingerprint
// HeaderProtection   *HeaderProtection
// CookieProtection   *CookieProtection

// Protection structures
type Protection struct {
    // Removed RequestCounter
    // Protection components
    TLSFingerprints    *TLSFingerprintProtection
    IPRateLimiter      *IPRateLimiter
    HandshakeProtection *TLSHandshakeProtection
    ASNChecker         *ASNChecker
    CloudflareIPs      *CloudflareIPRanges
    CookieProtection   *CookieProtection
    ContentCache       *ContentCache // New content cache component
    ServerStats        *ServerStats  // Add server stats
}

// TLS Fingerprint Protection
type TLSFingerprintProtection struct {
    sync.RWMutex
    knownFingerprints map[string]bool
    blocklist    map[string]time.Time
}

func NewTLSFingerprintProtection() *TLSFingerprintProtection {
    return &TLSFingerprintProtection{
        knownFingerprints: map[string]bool{
            // Chrome
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": true,
            // Firefox
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172,0-23-65281-10-11-35-16-5-34-13-18-51-45-43-27,29-23-24-25,0": true,
            // Safari (regular and private modes use the same fingerprint)
            "771,4865-4866-4867-49196-49195-49200-49199-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": true,
            // Edge
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25,0": true,
            // Firefox Private Browsing (different from regular Firefox)
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-13-18-51-45-43-27,29-23-24-25,0": true,
            // Chrome Incognito (may be different from regular Chrome)
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": true,
            // Edge InPrivate (with different extension set than regular Edge)
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25,0": true,
            // Additional common browser fingerprints
            "771,49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-0-23-35-13-5-18-16-11-10,29-23-24,0": true,
            "771,4865-4866-4867-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": true,
        },
        blocklist: make(map[string]time.Time),
    }
}

func (t *TLSFingerprintProtection) CheckFingerprint(hello *tls.ClientHelloInfo) error {
    // Generate JA3 fingerprint
    fingerprint := fmt.Sprintf("771,%v,%v,%v,0",
        strings.Trim(strings.Join(strings.Fields(fmt.Sprint(hello.CipherSuites)), "-"), "[]"),
        strings.Trim(strings.Join(strings.Fields(fmt.Sprint([]int{0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21})), "-"), "[]"),
        strings.Trim(strings.Join(strings.Fields(fmt.Sprint([]int{29, 23, 24})), "-"), "[]"))

    t.Lock()
    defer t.Unlock()

    // Check if fingerprint is known
    if t.knownFingerprints[fingerprint] {
        return nil // Allow known fingerprints
    }

    // Block unknown fingerprints with qrator message
    fmt.Printf("Unknown JA3 fingerprint: %s from IP: %s\n", fingerprint, hello.Conn.RemoteAddr().String()) // Log unknown fingerprint with IP only
    return fmt.Errorf("qrator HTTP403")
}

// IP Rate Limiter
type IPRateLimiter struct {
    sync.RWMutex
    limits map[string]*RateLimit
    requestCounts map[string]int32
    lastCleanup time.Time
    cleanupInterval time.Duration
    maxEntries int
}

type RateLimit struct {
    count    int32
    lastSeen time.Time
    blocked  bool
    blockUntil time.Time  // New field to explicitly track when the block expires
    // Add a field to track request rate for smart rate limiting
    requestTimes []time.Time  // Track times of recent requests
}

func NewIPRateLimiter() *IPRateLimiter {
    limiter := &IPRateLimiter{
        limits:         make(map[string]*RateLimit),
        requestCounts:  make(map[string]int32),
        lastCleanup:    time.Now(),
        cleanupInterval: 5 * time.Minute, // Clean up every 5 minutes
        maxEntries:     10000,            // Cap the number of IPs we track
    }
    
    // Start a background cleanup goroutine
    go func() {
        ticker := time.NewTicker(1 * time.Minute)
        defer ticker.Stop()
        
        for range ticker.C {
            limiter.cleanupRoutine()
        }
    }()
    
    return limiter
}

func (rl *IPRateLimiter) cleanupRoutine() {
    now := time.Now()
    
    rl.Lock()
    defer rl.Unlock()
    
    // Only run cleanup if enough time has passed
    if now.Sub(rl.lastCleanup) < rl.cleanupInterval {
        return
    }
    rl.lastCleanup = now
    
    // Remove old entries
    for ip, limit := range rl.limits {
        // If not seen in last 30 minutes and not blocked, remove
        if now.Sub(limit.lastSeen) > 30*time.Minute && !limit.blocked {
            delete(rl.limits, ip)
            delete(rl.requestCounts, ip)
        }
        // If blocked but block time expired, remove
        if limit.blocked && now.After(limit.blockUntil) {
            delete(rl.limits, ip)
            delete(rl.requestCounts, ip)
        }
    }
    
    // If we still have too many entries, remove the oldest ones
    if len(rl.limits) > rl.maxEntries {
        rl.evictOldest(rl.maxEntries / 5) // Remove 20% of oldest entries
    }
}

// New method to evict oldest entries
func (rl *IPRateLimiter) evictOldest(count int) {
    type ipLastSeen struct {
        ip string
        lastSeen time.Time
    }
    
    entries := make([]ipLastSeen, 0, len(rl.limits))
    for ip, limit := range rl.limits {
        // Don't evict blocked IPs
        if !limit.blocked {
            entries = append(entries, ipLastSeen{ip: ip, lastSeen: limit.lastSeen})
        }
    }
    
    // Sort by lastSeen (oldest first)
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].lastSeen.Before(entries[j].lastSeen)
    })
    
    // Remove oldest entries
    for i := 0; i < count && i < len(entries); i++ {
        delete(rl.limits, entries[i].ip)
        delete(rl.requestCounts, entries[i].ip)
    }
}

// IsAllowed checks if an IP is allowed to make a request
// Modified to be more tolerant of normal browsing and track request rate
func (rl *IPRateLimiter) IsAllowed(ip string) bool {
    now := time.Now()
    
    // First check with read lock for better concurrency
    rl.RLock()
    limit, exists := rl.limits[ip]
    rl.RUnlock()
    
    if exists {
        // If already blocked, check if block time has expired
        if limit.blocked {
            rl.Lock()
            // If block has expired, unblock
            if now.After(limit.blockUntil) {
                limit.blocked = false
                rl.requestCounts[ip] = 0
                // New code: Clear request history
                if limit.requestTimes != nil {
                    limit.requestTimes = nil
                }
                rl.Unlock()
            } else {
                rl.Unlock()
                return false // Still blocked
            }
        }
        
        rl.Lock()
        defer rl.Unlock()
        
        // Refresh our view of the limit
        limit, exists = rl.limits[ip]
        if !exists {
            // Should not happen normally, but just in case
            limit = &RateLimit{
                count: 1, 
                lastSeen: now,
                requestTimes: []time.Time{now},
            }
            rl.limits[ip] = limit
            rl.requestCounts[ip] = 1
            return true
        }
        
        // Update request history - limit to last 60 requests to save memory
        if limit.requestTimes == nil {
            limit.requestTimes = []time.Time{now}
        } else {
            limit.requestTimes = append(limit.requestTimes, now)
            if len(limit.requestTimes) > 60 {
                limit.requestTimes = limit.requestTimes[len(limit.requestTimes)-60:]
            }
        }
        
        // Calculate requests in the last 10 seconds - this detects rapid reloads/spam
        var recentRequests int
        tenSecondsAgo := now.Add(-10 * time.Second)
        for _, t := range limit.requestTimes {
            if t.After(tenSecondsAgo) {
                recentRequests++
            }
        }
        
        // Increment the total counter
        rl.requestCounts[ip]++
        limit.count = rl.requestCounts[ip]
        limit.lastSeen = now
        
        // New more intelligent and lenient rate limiting logic:
        // 1. Allow more total requests (150 instead of 100)
        // 2. But still detect and block very rapid reloads (>30 requests in 10 seconds)
        if limit.count > 150 || recentRequests > 30 {
            // Block for a shorter time (30 seconds instead of 60)
            limit.blocked = true
            limit.blockUntil = now.Add(30 * time.Second)
            return false
        }
        
        return true
    }
    
    // IP not seen before, add it
    rl.Lock()
    defer rl.Unlock()
    
    // Check again in case another goroutine added it while we were waiting
    if limit, exists = rl.limits[ip]; exists {
        limit.lastSeen = now
        return !limit.blocked
    }
    
    // If we have too many entries, cleanup before adding new one
    if len(rl.limits) >= rl.maxEntries {
        rl.evictOldest(rl.maxEntries / 10) // Remove 10% of oldest entries
    }
    
    // Add new IP
    rl.limits[ip] = &RateLimit{
        count:     1, 
        lastSeen:  now,
        blocked:   false,
        blockUntil: time.Time{}, // Zero time (not blocked)
        requestTimes: []time.Time{now}, // Initialize request times
    }
    rl.requestCounts[ip] = 1
    
    return true
}

// New method to return a JSON-formatted error for rate limiting
func (rl *IPRateLimiter) GetRateLimitDetails(ip string) (int, time.Time) {
    rl.RLock()
    defer rl.RUnlock()
    
    if limit, exists := rl.limits[ip]; exists && limit.blocked {
        secondsRemaining := int(limit.blockUntil.Sub(time.Now()).Seconds())
        if secondsRemaining < 0 {
            secondsRemaining = 0
        }
        return secondsRemaining, limit.blockUntil
    }
    
    return 0, time.Time{}
}

// TLS Handshake Protection
type TLSHandshakeProtection struct {
    sync.RWMutex
    attempts map[string]*HandshakeAttempt
}

type HandshakeAttempt struct {
    count     int
    lastTry   time.Time
    blocked   bool
    blockTime time.Time
}

func NewTLSHandshakeProtection() *TLSHandshakeProtection {
    return &TLSHandshakeProtection{
        attempts: make(map[string]*HandshakeAttempt),
    }
}

func (t *TLSHandshakeProtection) CheckHandshake(ip string) error {
    t.Lock()
    defer t.Unlock()
    
    now := time.Now()
    attempt, exists := t.attempts[ip]
    
    if exists && attempt.blocked {
        // If block has expired, unblock
        if now.After(attempt.blockTime) {
            attempt.blocked = false
            attempt.count = 0
            return nil
        }
        return fmt.Errorf("IP is blocked due to excessive handshake attempts")
    }
    
    if !exists {
        t.attempts[ip] = &HandshakeAttempt{
            count: 1,
            lastTry: now,
        }
        return nil
    }
    
    // Reset counter if more than 5 seconds have passed (increased from 1 second)
    if now.Sub(attempt.lastTry) > 5*time.Second {
        attempt.count = 1
        attempt.lastTry = now
        return nil
    }
    
    // Increment counter
    attempt.count++
    
    // Increased threshold from MAX_HANDSHAKES_PER_IP to MAX_HANDSHAKES_PER_IP + 5
    // This gives more leeway for legitimate users with multiple connections
    if attempt.count > MAX_HANDSHAKES_PER_IP + 5 {
        attempt.blocked = true
        // Reduced block time from HANDSHAKE_BAN_TIME to 3 minutes
        attempt.blockTime = now.Add(3 * time.Minute)
        return fmt.Errorf("Too many TLS handshake attempts")
    }
    
    return nil
}

// Cloudflare IP Ranges
type CloudflareIPRanges struct {
    sync.RWMutex
    IPv4 []string
    IPv6 []string
}

func NewCloudflareIPRanges() *CloudflareIPRanges {
    cf := &CloudflareIPRanges{}
    cf.UpdateRanges()
    return cf
}

func (cf *CloudflareIPRanges) UpdateRanges() {
    // Fetch IPv4 ranges
    resp, err := http.Get("https://www.cloudflare.com/ips-v4")
    if err == nil {
        body, _ := io.ReadAll(resp.Body)
        cf.Lock()
        cf.IPv4 = strings.Split(strings.TrimSpace(string(body)), "\n")
        cf.Unlock()
        resp.Body.Close()
    }

    // Fetch IPv6 ranges
    resp, err = http.Get("https://www.cloudflare.com/ips-v6")
    if err == nil {
        body, _ := io.ReadAll(resp.Body)
        cf.Lock()
        cf.IPv6 = strings.Split(strings.TrimSpace(string(body)), "\n")
        cf.Unlock()
        resp.Body.Close()
    }
}

func (cf *CloudflareIPRanges) IsCloudflareIP(ip string) bool {
    cf.RLock()
    defer cf.RUnlock()

    netIP := net.ParseIP(ip)
    if netIP == nil {
        return false
    }

    for _, cidrStr := range cf.IPv4 {
        _, cidr, err := net.ParseCIDR(cidrStr)
        if err != nil {
            continue
        }
        if cidr.Contains(netIP) {
            return true
        }
    }

    for _, cidrStr := range cf.IPv6 {
        _, cidr, err := net.ParseCIDR(cidrStr)
        if err != nil {
            continue
        }
        if cidr.Contains(netIP) {
            return true
        }
    }

    return false
}

// ASN Checker
type ASNChecker struct {
    sync.RWMutex
    blockedASNs map[string]bool
}

func NewASNChecker() *ASNChecker {
    return &ASNChecker{
        blockedASNs: map[string]bool{
            "AS14061": true, // DigitalOcean
            "AS16509": true, // Amazon AWS
            "AS15169": true, // Google Cloud
            "AS8075":  true, // Microsoft Azure
            // Add more blocked ASNs as needed
        },
    }
}

func (a *ASNChecker) IsBlockedASN(ip string) bool {
    // Since we're simplifying to just count requests, always return false
    // This means no ASN will be blocked
    return false
}

// Cookie Protection for JS Challenge
type CookieProtection struct {
    sync.RWMutex
    validCookies map[string]time.Time
}

func NewCookieProtection() *CookieProtection {
    return &CookieProtection{
        validCookies: make(map[string]time.Time),
    }
}

func (cp *CookieProtection) GenerateCookie() string {
    token := make([]byte, 32)
    for i := range token {
        token[i] = byte(rand.Intn(256))
    }
    cookieValue := base64.URLEncoding.EncodeToString(token)
    
    cp.Lock()
    cp.validCookies[cookieValue] = time.Now().Add(COOKIE_LIFETIME)
    cp.Unlock()
    
    return cookieValue
}

func (cp *CookieProtection) ValidateCookie(cookie string) bool {
    if cookie == "" {
        return false
    }

    cp.RLock()
    expiry, exists := cp.validCookies[cookie]
    cp.RUnlock()

    // If cookie doesn't exist in our registry but has the correct format,
    // we'll accept it for private browsing compatibility
    if !exists && len(cookie) >= 32 {
        // This is a relaxed check for private browsing - just ensure the cookie has a reasonable length
        // Add this cookie to our registry with a new expiry time
        cp.Lock()
        cp.validCookies[cookie] = time.Now().Add(COOKIE_LIFETIME)
        cp.Unlock()
        return true
    }

    if !exists {
        return false
    }

    // Check if cookie has expired
    if time.Now().After(expiry) {
        cp.Lock()
        delete(cp.validCookies, cookie)
        cp.Unlock()
        return false
    }

    return true
}

func (cp *CookieProtection) CleanupExpiredCookies() {
    cp.Lock()
    defer cp.Unlock()
    
    now := time.Now()
    for cookie, expiry := range cp.validCookies {
        if now.After(expiry) {
            delete(cp.validCookies, cookie)
        }
    }
}

// ContentCache provides caching of content from custom URLs
type ContentCache struct {
    sync.RWMutex
    cacheData        map[string]*CachedContent
    client           *fasthttp.Client
    expirationTime   time.Duration
    lastCleanup      time.Time
}

// CachedContent represents a single cached resource
type CachedContent struct {
    Content     []byte
    ContentType string
    LastFetched time.Time
    ExpiresAt   time.Time
    CookieVal   string
}

// NewContentCache creates a new content cache with a specified expiration time
func NewContentCache(expirationMinutes int) *ContentCache {
    return &ContentCache{
        cacheData:      make(map[string]*CachedContent),
        client:         &fasthttp.Client{},
        expirationTime: time.Duration(expirationMinutes) * time.Minute,
        lastCleanup:    time.Now(),
    }
}

// GetContent retrieves content from the cache or fetches it from the source URL if needed
func (cc *ContentCache) GetContent(cacheKey string, sourceURL string) (*CachedContent, error) {
    cc.RLock()
    cachedItem, exists := cc.cacheData[cacheKey]
    cc.RUnlock()
    
    // Return cached content if it exists and isn't expired
    if exists && time.Now().Before(cachedItem.ExpiresAt) {
        return cachedItem, nil
    }
    
    // Need to fetch the content
    cc.Lock()
    defer cc.Unlock()
    
    // Double-check after acquiring the lock
    cachedItem, exists = cc.cacheData[cacheKey]
    if exists && time.Now().Before(cachedItem.ExpiresAt) {
        return cachedItem, nil
    }
    
    // Fetch from the source URL
    req := fasthttp.AcquireRequest()
    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseRequest(req)
    defer fasthttp.ReleaseResponse(resp)
    
    req.SetRequestURI(sourceURL)
    req.Header.SetMethod("GET")
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")
    
    err := cc.client.Do(req, resp)
    if err != nil {
        return nil, err
    }
    
    // Handle non-200 status codes
    if resp.StatusCode() != fasthttp.StatusOK {
        // For 404 and other errors, we'll accept the content but log it
        // This lets us serve error pages or customized content rather than failing
        fmt.Printf("Warning: Source URL '%s' returned status code %d\n", sourceURL, resp.StatusCode())
    }
    
    // Create a new cached item, even for error pages
    content := make([]byte, len(resp.Body()))
    copy(content, resp.Body())
    
    // Generate a cookie value
    cookieVal := generateRandomString(32)
    
    contentType := string(resp.Header.ContentType())
    if contentType == "" {
        // Default to HTML if no content type was provided
        contentType = "text/html; charset=utf-8"
    }
    
    cachedItem = &CachedContent{
        Content:     content,
        ContentType: contentType,
        LastFetched: time.Now(),
        ExpiresAt:   time.Now().Add(cc.expirationTime),
        CookieVal:   cookieVal,
    }
    
    cc.cacheData[cacheKey] = cachedItem
    
    // Potentially clean up expired entries
    if time.Since(cc.lastCleanup) > 5*time.Minute {
        go cc.cleanupExpired()
    }
    
    return cachedItem, nil
}

// ValidateCookie checks if the provided cookie is valid for the cache key
func (cc *ContentCache) ValidateCookie(cacheKey string, cookie string) bool {
    cc.RLock()
    defer cc.RUnlock()
    
    cachedItem, exists := cc.cacheData[cacheKey]
    if !exists {
        return false
    }
    
    // For private browsing compatibility, be more lenient with cookie validation
    // Either match exactly OR just verify that a cookie exists with sufficient length
    return cachedItem.CookieVal == cookie || (cookie != "" && len(cookie) >= 16)
}

// cleanupExpired removes expired cache entries
func (cc *ContentCache) cleanupExpired() {
    cc.Lock()
    defer cc.Unlock()
    
    now := time.Now()
    cc.lastCleanup = now
    
    for key, item := range cc.cacheData {
        if now.After(item.ExpiresAt) {
            delete(cc.cacheData, key)
        }
    }
}

// Helper function to generate a random string for cookies
func generateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}

// ServerStats untuk melacak statistik server
type ServerStats struct {
    sync.RWMutex
    activeConnections int64
    totalAccepts     int64
    totalHandled     int64
    totalRequests    int64
    reading          int64
    writing          int64
    waiting          int64
    lastUpdate       time.Time
}

func NewServerStats() *ServerStats {
    return &ServerStats{
        lastUpdate: time.Now(),
    }
}

func (s *ServerStats) IncrementAccepts() {
    s.Lock()
    defer s.Unlock()
    s.totalAccepts++
    s.lastUpdate = time.Now()
}

func (s *ServerStats) IncrementHandled() {
    s.Lock()
    defer s.Unlock()
    s.totalHandled++
    s.lastUpdate = time.Now()
}

func (s *ServerStats) IncrementRequests() {
    s.Lock()
    defer s.Unlock()
    s.totalRequests++
    s.lastUpdate = time.Now()
}

func (s *ServerStats) SetActiveConnections(count int64) {
    s.Lock()
    defer s.Unlock()
    s.activeConnections = count
    s.lastUpdate = time.Now()
}

func (s *ServerStats) SetReading(count int64) {
    s.Lock()
    defer s.Unlock()
    s.reading = count
    s.lastUpdate = time.Now()
}

func (s *ServerStats) SetWriting(count int64) {
    s.Lock()
    defer s.Unlock()
    s.writing = count
    s.lastUpdate = time.Now()
}

func (s *ServerStats) SetWaiting(count int64) {
    s.Lock()
    defer s.Unlock()
    s.waiting = count
    s.lastUpdate = time.Now()
}

func (s *ServerStats) GetStats() map[string]int64 {
    s.RLock()
    defer s.RUnlock()
    return map[string]int64{
        "activeConnections": s.activeConnections,
        "totalAccepts":     s.totalAccepts,
        "totalHandled":     s.totalHandled,
        "totalRequests":    s.totalRequests,
        "reading":          s.reading,
        "writing":          s.writing,
        "waiting":          s.waiting,
    }
}

// Main server setup
func main() {
    // Initialize random seed
    rand.Seed(time.Now().UnixNano())
    
    // Initialize protection systems
    protection := &Protection{
        TLSFingerprints:     NewTLSFingerprintProtection(),
        IPRateLimiter:      NewIPRateLimiter(),
        HandshakeProtection: NewTLSHandshakeProtection(),
        ASNChecker:         NewASNChecker(),
        CloudflareIPs:       NewCloudflareIPRanges(),
        CookieProtection:    NewCookieProtection(),
        ContentCache:        NewContentCache(30), // 30 minutes expiration
        ServerStats:         NewServerStats(),    // Initialize server stats
    }

    // Start cookie cleanup routine
    go func() {
        for {
            protection.CookieProtection.CleanupExpiredCookies()
            time.Sleep(5 * time.Minute)
        }
    }()
    
    // Start content cache cleanup routine
    go func() {
        for {
            protection.ContentCache.cleanupExpired()
            time.Sleep(10 * time.Minute)
        }
    }()

    // Start handshake cleanup routine
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()
        
        for range ticker.C {
            protection.HandshakeProtection.cleanupExpiredAttempts()
        }
    }()

    // Get server's IP address
    serverIP := ""
    addrs, err := net.InterfaceAddrs()
    if err == nil {
        for _, addr := range addrs {
            if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
                if ipnet.IP.To4() != nil {
                    serverIP = ipnet.IP.String()
                    break
                }
            }
        }
    }
    if serverIP == "" {
        serverIP = "0.0.0.0" // Fallback to all interfaces if can't determine IP
    }

    // Load TLS certificates
    cert, err := tls.LoadX509KeyPair(
        "/etc/letsencrypt/live/vx.zerostresser.ru/fullchain.pem",
        "/etc/letsencrypt/live/vx.zerostresser.ru/privkey.pem",
    )
    if err != nil {
        os.Exit(1)
    }

    // Configure TLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:  tls.VersionTLS13, // Force TLS 1.3 only
        MaxVersion:  tls.VersionTLS13,
        
        // Lock down cipher suites
        CipherSuites: []uint16{
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
        
        // Curve preferences
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP384,
        },
        
        // Additional security options
        PreferServerCipherSuites: true,
        SessionTicketsDisabled: true, // Disable session tickets
        Renegotiation: tls.RenegotiateNever,
        
        // Allow IP-based access
        ServerName: serverIP,  // Use server's IP address
        InsecureSkipVerify: true, // Skip certificate hostname verification
        
        GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
            ip, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())

            // Skip checks for Cloudflare IPs
            if protection.CloudflareIPs.IsCloudflareIP(ip) {
                return nil, nil
            }

            // Check handshake rate
            if err := protection.HandshakeProtection.CheckHandshake(ip); err != nil {
                return nil, err
            }

            // Skip TLS version check for certain known user agents to fix connection reset
            userAgent := ""
            if len(hello.SupportedProtos) > 0 {
                // Some clients put user agent info in ALPN
                for _, proto := range hello.SupportedProtos {
                    if strings.Contains(strings.ToLower(proto), "mozilla") || 
                       strings.Contains(strings.ToLower(proto), "chrome") ||
                       strings.Contains(strings.ToLower(proto), "safari") ||
                       strings.Contains(strings.ToLower(proto), "edge") {
                        userAgent = proto
                        break
                    }
                }
            }

            // More lenient TLS version checking
            hasValidVersion := false
            for _, version := range hello.SupportedVersions {
                // Accept TLS 1.2 and 1.3
                if version == tls.VersionTLS13 || version == tls.VersionTLS12 {
                    hasValidVersion = true
                    break
                }
            }
            
            // Only block if clearly suspicious, allow more legitimate clients through
            if !hasValidVersion && userAgent == "" && len(hello.SupportedVersions) < 2 {
                return nil, fmt.Errorf("Modern TLS version required")
            }

            return nil, nil
        },
    }

    // Create server with TLS config
    var server *fasthttp.Server
    server = &fasthttp.Server{
        Handler: func(ctx *fasthttp.RequestCtx) {
            // Increment total requests
            protection.ServerStats.IncrementRequests()
            
            // Update active connections
            protection.ServerStats.SetActiveConnections(int64(server.GetOpenConnectionsCount()))
            
            // Update reading/writing/waiting counts
            // Since we can't access concurrency directly, we'll estimate:
            // - Reading: 20% of active connections
            // - Writing: 30% of active connections
            // - Waiting: 50% of active connections
            activeConnections := server.GetOpenConnectionsCount()
            protection.ServerStats.SetReading(int64(float64(activeConnections) * 0.2))
            protection.ServerStats.SetWriting(int64(float64(activeConnections) * 0.3))
            protection.ServerStats.SetWaiting(int64(float64(activeConnections) * 0.5))

            ip := string(ctx.Request.Header.Peek("CF-Connecting-IP"))
            if ip == "" {
                ip = ctx.RemoteIP().String()
            }

            // Handle stats endpoint without protection
            if string(ctx.Path()) == "/iniapiajg/stats" {
                stats := protection.ServerStats.GetStats()
                ctx.SetContentType("text/plain")
                fmt.Fprintf(ctx, "Active connections: %d\n", stats["activeConnections"])
                fmt.Fprintf(ctx, "server accepts handled requests\n")
                fmt.Fprintf(ctx, " %d %d %d\n", 
                    stats["totalAccepts"], 
                    stats["totalHandled"], 
                    stats["totalRequests"])
                fmt.Fprintf(ctx, "Reading: %d Writing: %d Waiting: %d\n",
                    stats["reading"],
                    stats["writing"],
                    stats["waiting"])
                return
            }

            // Allow Cloudflare IPs
            if protection.CloudflareIPs.IsCloudflareIP(ip) {
                protection.ServerStats.IncrementAccepts()
                protection.ServerStats.IncrementHandled()
                handleRequest(ctx, protection)
                return
            }

            // Check bypass token
            if string(ctx.Request.Header.Peek("X-Bypass-Token")) == BYPASS_TOKEN {
                handleRequest(ctx, protection)
                return
            }

            // Check rate limits
            if !protection.IPRateLimiter.IsAllowed(ip) {
                // Modified to return JSON response with rate limit information
                seconds, unblockTime := protection.IPRateLimiter.GetRateLimitDetails(ip)
                
                // Set content type to JSON
                ctx.SetContentType("application/json")
                ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
                
                // Create informative JSON response
                jsonResponse := map[string]interface{}{
                    "error": "Rate limit exceeded",
                    "status": 429,
                    "message": "Too many requests from your IP address",
                    "seconds_remaining": seconds,
                    "retry_after": seconds,
                    "unblock_time": unblockTime.Format(time.RFC3339),
                }
                
                // Add retry-after header
                ctx.Response.Header.Set("Retry-After", fmt.Sprintf("%d", seconds))
                
                // Serialize and set JSON response
                if jsonData, err := json.Marshal(jsonResponse); err == nil {
                    ctx.SetBody(jsonData)
                } else {
                    // Fallback if JSON marshaling fails
                    ctx.SetBodyString(`{"error":"Rate limit exceeded","status":429}`)
                }
                
                return
            }

            // Check ASN
            if protection.ASNChecker.IsBlockedASN(ip) {
                ctx.SetStatusCode(fasthttp.StatusForbidden)
                return
            }

            // Check User-Agent
            userAgent := string(ctx.UserAgent())
            if !isValidUserAgent(userAgent) {
                ctx.SetStatusCode(fasthttp.StatusForbidden)
                return
            }

            handleRequest(ctx, protection)
        },
        ReadTimeout:  60 * time.Second,  // Reduced from 130s to a more reasonable timeout
        WriteTimeout: 60 * time.Second,  // Reduced from 130s to a more reasonable timeout
        MaxRequestBodySize: 10 * 1024 * 1024, // 10MB body size limit
        NoDefaultContentType: true,     // Don't add content-type automatically
        CloseOnShutdown: true,          // Close idle connections on shutdown
        DisableKeepalive: false,        // Enable keepalive
        TCPKeepalive: true,             // Enable TCP keepalive
        TCPKeepalivePeriod: 60 * time.Second, // 60s keepalive period
        MaxKeepaliveDuration: 300 * time.Second, // Max 5 minutes for keepalive
        ReduceMemoryUsage: true,        // Reduce memory usage where possible
        GetOnly: false,                 // Allow all HTTP methods
        DisablePreParseMultipartForm: true, // Don't parse multipart forms automatically
        TLSConfig:   tlsConfig,
        ConnState: func(conn net.Conn, state fasthttp.ConnState) {
            if state == fasthttp.StateClosed {
                // Don't try to call CloseWrite as it can cause connection reset issues
                // Just let the connection close naturally
            }
        },
    }

    // Start server
    if err := server.ListenAndServeTLS("0.0.0.0:443",
        "/etc/letsencrypt/live/vx.zerostresser.ru/fullchain.pem",
        "/etc/letsencrypt/live/vx.zerostresser.ru/privkey.pem",
    ); err != nil {
        os.Exit(1)
    }
}

// Helper function to show the JS challenger
func showJSChallenger(ctx *fasthttp.RequestCtx, protection *Protection, path string, ipAddr string, userAgent string) {
    challengeID := fmt.Sprintf("%d", rand.Int63())
    
    // HTML ส่วนหัวและ CSS ยังคงเหมือนเดิมเพื่อความสะดวกในการแก้ไข UI
    jsChallengePage := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Check</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <style>
        body {
            background-color:rgb(0, 0, 0);
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 0;
        }
        .container {
            text-align: center;
            width: 80%%;
            max-width: 600px;
        }
        .loading {
            display: inline-block;
            width: 50px;
            height: 50px;
            border: 3px solid rgba(250, 13, 13, 0.3);
            border-radius: 50%%;
            border-top-color: #000;
            animation: spin 1s ease-in-out infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .message {
            margin-top: 20px;
            color: #ffffff;
        }
        .instructions {
            margin-top: 15px;
            color: #ff9900;
            font-weight: bold;
            padding: 10px;
            border: 1px dashed #ff9900;
            border-radius: 5px;
            background-color: rgba(255, 153, 0, 0.1);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%% { opacity: 0.7; }
            50%% { opacity: 1; }
            100%% { opacity: 0.7; }
        }
        .error-message {
            color: #ff5555;
            font-weight: bold;
            margin-top: 20px;
            padding: 15px;
            border: 2px solid #ff5555;
            border-radius: 5px;
            background-color: rgba(255, 0, 0, 0.1);
        }
        .browser-info {
            font-size: 12px;
            color: #aaaaaa;
            margin-top: 20px;
        }
        #mouse-trap {
            position: absolute;
            width: 100%%;
            height: 100%%;
            top: 0;
            left: 0;
            z-index: -1;
        }
        .hidden {
            display: none;
        }
        #hover-test {
            width: 1px;
            height: 1px;
            position: absolute;
            opacity: 0.01;
            top: 50%%;
            left: 50%%;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="loading"></div>
        <div class="message">Security check in progress...</div>
        
        <div class="instructions">
            ⚠️ <br>
            Please move your mouse to verify you're human
    </div>
    
        <p class="browser-info">If this check doesn't complete, please try refreshing the page or disable private browsing.</p>
        
        <noscript>
            <div class="error-message">
                <p>JavaScript is required to access this website.</p>
                <p>Please enable JavaScript in your browser settings and refresh the page.</p>
                <p>Enable javascript in your browser settings and refresh the page.</p>
                <p>Enable javascript in your browser settings and refresh the page.</p>
            </div>
        </noscript>
        
        <div id="mouse-trap"></div>
        <div id="hover-test"></div>
        <div id="botResult" class="hidden"></div>
    </div>
    
    <!-- แก้ไข JavaScript เพื่อส่งคำขอไปยัง PHP เมื่อผ่านการตรวจสอบ -->
    <script>
    /* Challenge ID: %s */
        (function() {
        // Define challengeID at the top level of the script
        var challengeID = "%s";
        var _0x4a8e=['webdriver','callSelenium','_Selenium_IDE_Recorder','__selenium_evaluate','__selenium_unwrapped','selenium','$cdc_asdjflasutopfhvcZLmcfl_','$wdc_asdjflasutopfhvcZLmcfl_','$chrome_asyncScriptInfo','__webdriver_script_fn','languages','length','language','plugins','mimeTypes','outerHeight','outerWidth','userAgent','toLowerCase','indexOf','headless','phantomjs','nightmare','electron','__nightmare','_phantom','callPhantom','puppeteer','__puppeteer_evaluation_script__','permissions','query','then','state','createElement','canvas','getContext','webgl','experimental-webgl','getExtension','WEBGL_debug_renderer_info','getParameter','UNMASKED_VENDOR_WEBGL','UNMASKED_RENDERER_WEBGL','SwiftShader','OffScreen','llvmpipe','innerWidth','documentElement','clientWidth','body','clientWidth','innerHeight','clientHeight','clientHeight','addEventListener','mousemove','innerHTML','✅<br>Mouse\x20verification\x20completed','style','color','#22cc22','borderColor','backgroundColor','rgba(34,\x20204,\x2034,\x200.1)','click','keydown','cookie','testcookie=1','testcookie','testcookie=;\x20expires=Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT','DOMContentLoaded','getElementsByTagName','noscript','display','none','querySelector','.message','textContent','Access\x20denied.\x20This\x20website\x20does\x20not\x20allow\x20automated\x20access.','.instructions','❌<br>Headless\x20Chrome\x20detected.\x20Automated\x20browsing\x20is\x20not\x20allowed.','#ff5555','rgba(255,\x200,\x200,\x200.1)','❌<br>WebDriver\x20detected.\x20Automated\x20browsing\x20is\x20not\x20allowed.','❌<br>Browser\x20language\x20validation\x20failed.\x20Check\x20your\x20browser\x20settings.','❌<br>Browser\x20feature\x20check\x20failed.\x20Missing:\x20','slice','join','Verification\x20successful,\x20please\x20wait...','location','reload','An\x20error\x20occurred.\x20Please\x20refresh\x20the\x20page\x20or\x20try\x20a\x20different\x20browser.','error','screenSizeValid','mouseDetected','mouseMove','userInteraction','webdriverDetected','automationDetected','headlessChromeDetected','languageValid','featuresValid','missingFeatures','botScore','open','POST','/set_cookie.php','setRequestHeader','Content-Type','application/x-www-form-urlencoded','onreadystatechange','readyState','status','An\x20error\x20occurred\x20during\x20verification.\x20Please\x20try\x20again.','pathname','send','path=','encodeURIComponent','&challenge_id=%s&user_verified=true','localStorage','setItem','_test','removeItem','sessionStorage','WebGL','Web\x20Audio','AudioContext','webkitAudioContext','Web\x20Crypto\x20API','crypto','subtle','IndexedDB','indexedDB','Screen\x20Properties','screen','width','Screen/Window\x20Ratio','abs','Touch\x20Events','ontouchstart','function','Please\x20enable\x20cookies\x20to\x20continue\x20or\x20disable\x20private\x20browsing.'];
        
        // Fix missing function: Add the _0x5a16 function definition
        (function(_0x5c0b0a,_0x4a8e1a){var _0x5a1621=function(_0x2d8f05){while(--_0x2d8f05){_0x5c0b0a['push'](_0x5c0b0a['shift']());}};_0x5a1621(++_0x4a8e1a);}(_0x4a8e,0x1c8));
        var _0x5a16=function(_0x5c0b0a,_0x4a8e1a){_0x5c0b0a=_0x5c0b0a-0x0;var _0x5a1621=_0x4a8e[_0x5c0b0a];return _0x5a1621;};
        
        // ตัวแปรสำหรับเก็บข้อมูลการตรวจสอบ bot
        var botChecks={
            'screenSizeValid':!![],
            'mouseDetected':![],
            'mouseMove':![],
            'userInteraction':![],
            'webdriverDetected':![],
            'automationDetected':![],
            'headlessChromeDetected':![],
            'languageValid':![],
            'featuresValid':![],
            'missingFeatures':[],
            'botScore':0x0
        };
        
        // ฟังก์ชันสำหรับส่งข้อมูลไปยัง PHP เมื่อผ่านการตรวจสอบ
        function sendVerificationToPHP(callback){
            try {
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "/set_cookie.php", true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4) {
                        if (xhr.status === 200) {
                            if (callback) callback();
                        } else {
                            document.querySelector('.message').textContent = 'An error occurred during verification. Please try again.';
                        }
                    }
                };
                
                var path = window.location.pathname;
                xhr.send("path=" + encodeURIComponent(path) + "&challenge_id=" + challengeID + "&user_verified=true");
            } catch(e) {
                console.error("XHR Error:", e);
                document.querySelector('.message').textContent = 'Connection error. Please try refreshing the page.';
            }
        }
        
        // ฟังก์ชันประเมินคุณสมบัติที่คาดหวังของเบราว์เซอร์
        function evaluateBrowserFeatures(){
            var _0x5c0b0a=[];
            var _0x4a8e1a=0x0;
            
            try{
                if(!window.localStorage){
                    _0x5c0b0a.push('localStorage');
                    _0x4a8e1a+=5; // Reduced from 15
                }else{
                    window.localStorage.setItem(_0x5a16('0x6e'),'1');
                    window.localStorage.removeItem(_0x5a16('0x6e'));
                }
            }catch(_0x2d8f05){
                _0x5c0b0a.push('localStorage');
                _0x4a8e1a+=5; // Reduced from 15
            }
            
            try{
                if(!window.sessionStorage){
                    _0x5c0b0a.push('sessionStorage');
                    _0x4a8e1a+=3; // Reduced from 10
                }
            }catch(_0x2d8f05){
                _0x5c0b0a.push('sessionStorage');
                _0x4a8e1a+=3; // Reduced from 10
            }
            
            try{
                var _0x5a1621=document.createElement(_0x5a16('0x33'));
                var _0x3a9e8f=_0x5a1621[_0x5a16('0x34')](_0x5a16('0x35'))||_0x5a1621[_0x5a16('0x34')](_0x5a16('0x36'));
                if(!_0x3a9e8f){
                    _0x5c0b0a['push'](_0x5a16('0x71'));
                    _0x4a8e1a+=5; // Reduced from 20
                }
            }catch(_0x2d8f05){
                _0x5c0b0a['push'](_0x5a16('0x71'));
                _0x4a8e1a+=5; // Reduced from 20
            }
            
            if(!window[_0x5a16('0x72')]&&!window[_0x5a16('0x73')]){
                _0x5c0b0a.push('Web Audio');
                _0x4a8e1a+=3; // Reduced from 10
            }
            
            if(!window[_0x5a16('0x75')]||!window[_0x5a16('0x75')][_0x5a16('0x76')]){
                _0x5c0b0a.push('Web Crypto API');
                _0x4a8e1a+=0xf;
            }
            
            if(!window[_0x5a16('0x78')]){
                _0x5c0b0a.push('IndexedDB');
                _0x4a8e1a+=0xa;
            }
            
            if(!window[_0x5a16('0x7a')]||typeof window[_0x5a16('0x7a')][_0x5a16('0x7b')]!=='number'||window[_0x5a16('0x7a')][_0x5a16('0x7b')]===0x0){
                _0x5c0b0a.push('Screen Properties');
                _0x4a8e1a+=0x14;
            }
            
            if(window[_0x5a16('0x7a')]&&window[_0x5a16('0x16')]&&window[_0x5a16('0x15')]){
                var _0x2d8f05=window[_0x5a16('0x7a')][_0x5a16('0x7b')]/window[_0x5a16('0x7a')]['height'];
                var _0x5c0b0a=window[_0x5a16('0x16')]/window[_0x5a16('0x15')];
                
                var _0x4a8e1a=Math[_0x5a16('0x7d')](_0x2d8f05-_0x5c0b0a);
                if(_0x4a8e1a>0.5){
                    _0x5c0b0a.push('Screen/Window Ratio');
                    _0x4a8e1a+=0xf;
                }
            }
            
            if(window[_0x5a16('0x7f')]!==undefined&&typeof window[_0x5a16('0x7f')]!==_0x5a16('0x80')){
                _0x5c0b0a.push('Touch Events');
                _0x4a8e1a+=0xa;
            }
            
            botChecks['missingFeatures']=_0x5c0b0a;
            botChecks['featuresValid']=(_0x4a8e1a<0x1e);
            
            botChecks['botScore']+=_0x4a8e1a;
            
            return _0x4a8e1a<0x1e;
        }
        
        // ฟังก์ชั่นตรวจสอบ WebDriver
        function detectWebDriver(){
            if(navigator[_0x5a16('0x0')]===!![]){
                botChecks[_0x5a16('0x5a')]=!![];
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            var _0x5c0b0a=[_0x5a16('0x1'),_0x5a16('0x2'),_0x5a16('0x3'),_0x5a16('0x4')];
            for(var _0x4a8e1a=0x0;_0x4a8e1a<_0x5c0b0a[_0x5a16('0xb')];_0x4a8e1a++){
                if(_0x5c0b0a[_0x4a8e1a] in window||_0x5c0b0a[_0x4a8e1a] in document){
                    botChecks[_0x5a16('0x5a')]=!![];
                    botChecks[_0x5a16('0x5c')]+=0x32;
                    return!![];
                }
            }
            
            if(_0x5a16('0x5') in window||_0x5a16('0x5') in document){
                botChecks[_0x5a16('0x5a')]=!![];
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            if(document[_0x5a16('0x6')]!==undefined||document[_0x5a16('0x7')]!==undefined||document[_0x5a16('0x8')]!==undefined){
                botChecks[_0x5a16('0x5a')]=!![];
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            if(_0x5a16('0x9') in document){
                botChecks[_0x5a16('0x5a')]=!![];
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            if(document._selenium !== undefined || document.__webdriver_evaluate !== undefined || document.__selenium_evaluate !== undefined){
                botChecks[_0x5a16('0x5a')]=!![];
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            if('__puppeteer_evaluation_script__' in document){
                botChecks[_0x5a16('0x5a')]=!![];
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            return![];
        }

        // เพิ่มฟังก์ชันตรวจสอบการตั้งค่าภาษา
        function checkLanguagePreferences(){
            // Check if languages array exists
            if(!navigator.languages) {
                // Old browsers may not have this property
                // Don't penalize heavily if language is otherwise defined
                if(navigator.language) {
                    botChecks[_0x5a16('0x5c')] += 5;
                } else {
                    botChecks[_0x5a16('0x5c')] += 15;
                }
                return false;
            }
            
            // Some browsers may legitimately have empty languages array
            // Only add small score if languages array is empty
            if(navigator.languages.length === 0) {
                if(navigator.language) {
                    // Has language but no languages array
                    botChecks[_0x5a16('0x5c')] += 5;
                } else {
                    // No language information at all - suspicious
                    botChecks[_0x5a16('0x5c')] += 15;
                }
                return false;
            }
            
            // Everything looks normal
            botChecks['languageValid'] = true;
            return true;
        }
        
        // ตรวจสอบ Automation อื่นๆ
        function detectAutomation(){
            var suspiciousCount = 0;
            
            // Explicit Selenium/Webdriver properties - very strong signals
            var automationProps = [
                'webdriver', 
                '_Selenium_IDE_Recorder', 
                'callSelenium', 
                '_selenium', 
                '__webdriver_script_fn', 
                'selenium'
            ];
            
            for(var i = 0; i < automationProps.length; i++) {
                if(automationProps[i] in window || automationProps[i] in document) {
                    botChecks[_0x5a16('0x5c')] += 30;
                    botChecks[_0x5a16('0x5b')] = true;
                    return true;
                }
            }
            
            // Don't penalize for plugins or mimeTypes - many normal browsers have none
            
            // VERY unusual situation: zero width/height - strong headless signal
            if(window.outerHeight === 0 || window.outerWidth === 0) {
                suspiciousCount++;
                botChecks[_0x5a16('0x5c')] += 15;
            }
            
            // Look for explicit headless strings in user agent (case insensitive)
            var ua = navigator.userAgent.toLowerCase();
            if(ua.indexOf('headlesschrome') !== -1) { // Only exact match
                suspiciousCount++;
                botChecks[_0x5a16('0x5c')] += 25;
            }
            
            // Only flag automation if multiple strong signals are present
            if(suspiciousCount >= 2) {
                botChecks[_0x5a16('0x5b')] = true;
                return true;
            }
            
            return false;
        }
        
        // ตรวจสอบ Headless Chrome
        function detectHeadlessChrome(){
            var _0x5c0b0a=![];
            
            var _0x4a8e1a=navigator[_0x5a16('0x11')][_0x5a16('0x12')]();
            if(_0x4a8e1a[_0x5a16('0x13')]('headlesschrome')!==-0x1){
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            if(navigator[_0x5a16('0xa')][_0x5a16('0xb')]===0x0){
                _0x5c0b0a=!![];
                botChecks[_0x5a16('0x5c')]+=0xa;
            }
            
            try{
                navigator[_0x5a16('0x1d')][_0x5a16('0x1e')]({'name':'notifications'})[_0x5a16('0x1f')](function(_0x5a1621){
                    if(_0x5a1621[_0x5a16('0x20')]==='denied'){
                        botChecks[_0x5a16('0x5c')]+=0x5;
                    }
                });
            }catch(_0x5a1621){}
            
            // Simplified WebGL detection to avoid errors
            try {
                // Simple WebGL check without accessing problematic properties
                var canvas = document.createElement('canvas');
                var gl = null;
                
                try {
                    gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                } catch (e) {
                    // Failed to get WebGL context
                }
                
                if (gl) {
                    // We have a valid WebGL context, check renderer info safely
                    var debugInfo = null;
                    
                    // Don't try to access UNMASKED properties directly
                    try {
                        debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    } catch (e) {
                        // Extension not available
                    }
                    
                    if (debugInfo) {
                        // Check for headless indicators in the renderer safely
                        try {
                            // Get renderer indirectly
                            var renderer = "";
                            
                            // Instead of directly accessing UNMASKED_RENDERER_WEBGL property
                            // Try to detect if we're running in a headless environment
                            // by checking canvas size limitations
                            
                            // Create a very large canvas as a test
                            canvas.width = 4000;
                            canvas.height = 4000;
                            
                            // Check if canvas dimensions were limited
                            if (canvas.width != 4000 || canvas.height != 4000) {
                                _0x5c0b0a = !![];
                                botChecks[_0x5a16('0x5c')] += 0xf;
                            }
                            
                            // Another headless detection: check if reading pixels works properly
                            var pixels = new Uint8Array(4);
                            gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
                            
                            // In some headless environments, this will return all zeros
                            if (pixels[0] === 0 && pixels[1] === 0 && pixels[2] === 0 && pixels[3] === 0) {
                                _0x5c0b0a = !![];
                                botChecks[_0x5a16('0x5c')] += 0xf;
                            }
                        } catch (e) {
                            // Ignore errors
                        }
                    }
                }
            } catch (e) {
                // Ignore any WebGL errors
            }
            
            if(_0x5c0b0a&&botChecks[_0x5a16('0x5c')]>=0x19){
                botChecks[_0x5a16('0x5c')]+=0x32;
                return!![];
            }
            
            return![];
        }
        
        // ตรวจสอบขนาดหน้าจอ
        function checkScreenSize(){
            var _0x5c0b0a=window.innerWidth||document.documentElement.clientWidth||document.body.clientWidth;
            var _0x4a8e1a=window.innerHeight||document.documentElement.clientHeight||document.body.clientHeight;
            
            if(_0x5c0b0a<=0x0||_0x4a8e1a<=0x0||_0x5c0b0a>0x2710||_0x4a8e1a>0x2710){
                botChecks[_0x5a16('0x5c')]+=0x14;
            }else if(_0x5c0b0a<0x64||_0x4a8e1a<0x64){
                botChecks[_0x5a16('0x5c')]+=0xa;
            }else{
                botChecks[_0x5a16('0x56')]=!![];
            }
        }
        
        // ตรวจสอบการเคลื่อนไหวของเมาส์
        var mouseMoveCount=0x0;
        var instructionsElem=document.querySelector('.instructions');
        
        document.addEventListener(_0x5a16('0x37'),function(_0x5c0b0a){
            mouseMoveCount++;
            
            if(mouseMoveCount>=0x3){
                botChecks[_0x5a16('0x58')]=!![];
                botChecks[_0x5a16('0x57')]=!![];
                
                if(instructionsElem){
                    instructionsElem.innerHTML=_0x5a16('0x39');
                    instructionsElem.style.color=_0x5a16('0x3c');
                    instructionsElem.style.borderColor=_0x5a16('0x3c');
                    instructionsElem.style.backgroundColor=_0x5a16('0x3f');
                }
                
                if(botChecks[_0x5a16('0x5c')]>0x0){
                    botChecks[_0x5a16('0x5c')]-=0x5;
                    if(botChecks[_0x5a16('0x5c')]<0x0)botChecks[_0x5a16('0x5c')]=0x0;
                }
            }
        });
        
        // อื่นๆ
        document.addEventListener(_0x5a16('0x40'),function(){
            botChecks[_0x5a16('0x59')]=!![];
            botChecks[_0x5a16('0x57')]=!![];
            
            if(botChecks[_0x5a16('0x5c')]>0x0){
                botChecks[_0x5a16('0x5c')]-=0xa;
                if(botChecks[_0x5a16('0x5c')]<0x0)botChecks[_0x5a16('0x5c')]=0x0;
            }
        });
        
        document.addEventListener(_0x5a16('0x41'),function(){
            botChecks[_0x5a16('0x59')]=!![];
            
            if(botChecks[_0x5a16('0x5c')]>0x0){
                botChecks[_0x5a16('0x5c')]-=0x5;
                if(botChecks[_0x5a16('0x5c')]<0x0)botChecks[_0x5a16('0x5c')]=0x0;
            }
        });
        
        // ตรวจสอบ cookies
        function areCookiesEnabled(){
            try{
                // More reliable cookie check
                var testCookie = "cookietest=1";
                document.cookie = testCookie;
                var cookieEnabled = document.cookie.indexOf("cookietest=") !== -1;
                
                // Clean up test cookie
                document.cookie = "cookietest=1; expires=Thu, 01-Jan-1970 00:00:01 GMT";
                
                return cookieEnabled;
            }catch(e){
                console.error("Cookie check error:", e);
                // Return true to avoid blocking users with cookie-related issues
                return true;
            }
        }
        
        // ซ่อน noscript warning
        document.addEventListener(_0x5a16('0x46'),function(){
            var _0x5c0b0a=document.getElementsByTagName(_0x5a16('0x48'));
            for(var _0x4a8e1a=0x0;_0x4a8e1a<_0x5c0b0a[_0x5a16('0xb')];_0x4a8e1a++){
                if(_0x5c0b0a[_0x4a8e1a].style){
                    _0x5c0b0a[_0x4a8e1a].style.display=_0x5a16('0x4a');
                }
            }
        });
        
        // ดำเนินการตรวจสอบต่างๆ
        checkScreenSize();
        detectWebDriver();
        
        // Skip problematic detection methods entirely
        /*
        try {
            detectAutomation();
        } catch(e) {
            console.error("Automation detection error: " + e.message);
        }
        
        try {
            detectHeadlessChrome();
        } catch(e) {
            console.error("Headless Chrome detection error: " + e.message);
            // If WebGL detection fails, we'll just skip it
        }
        */
        
        // Just set default values for these checks since they're causing errors
        botChecks['automationDetected'] = false;
        botChecks['headlessChromeDetected'] = false;
        
        // Also set WebGL feature to valid to avoid common false positives
        var missingWebGLIndex = botChecks.missingFeatures ? botChecks.missingFeatures.indexOf('WebGL') : -1;
        if (missingWebGLIndex > -1) {
            botChecks.missingFeatures.splice(missingWebGLIndex, 1);
            // Reduce the bot score by at least 5 to compensate for WebGL
            botChecks.botScore = Math.max(0, (botChecks.botScore || 0) - 5);
        }
        
        // Try simple bot detection methods that don't use problematic features
        try {
            detectSimpleBots();
        } catch(e) {
            console.error("Simple bot detection error: " + e.message);
        }
        
        checkLanguagePreferences();
        evaluateBrowserFeatures();
        
        // New simplified detection function that doesn't use WebGL
        function detectSimpleBots() {
            // Only detect extremely obvious automation indicators
            
            // 1. Empty user agent - a very strong signal
            if (navigator.userAgent === "") {
                botChecks['automationDetected'] = true;
                botChecks[_0x5a16('0x5c')] += 0x1e;
                return;
            }
            
            // 2. Only mark as headless if explicit "HeadlessChrome" string is found
            // This is a near-perfect signal and won't catch regular Chrome
            if (navigator.userAgent.indexOf("HeadlessChrome") !== -1) {
                botChecks['headlessChromeDetected'] = true;
                botChecks[_0x5a16('0x5c')] += 0x1e;
                return;
            }
            
            // 3. Only detect automation with very strong signals that don't exist in real browsers
            if ('webdriver' in navigator && navigator.webdriver === true) {
                botChecks['webdriverDetected'] = true;
                botChecks[_0x5a16('0x5c')] += 0x32;
                return;
            }
            
            // 4. Explicit automation objects that don't exist in real browsers
            var automationObjects = [
                '_selenium', 
                '__selenium_evaluate',
                '__selenium_unwrapped',
                'callSelenium',
                '_Selenium_IDE_Recorder',
                '__nightmare',
                '__puppeteer_evaluation_script__'
            ];
            
            for (var i = 0; i < automationObjects.length; i++) {
                if (automationObjects[i] in window || automationObjects[i] in document) {
                    botChecks['automationDetected'] = true;
                    botChecks[_0x5a16('0x5c')] += 0x1e;
                    return;
                }
            }
            
            // 5. Zero dimensions - a very reliable signal for headless
            if (window.outerHeight === 0 && window.outerWidth === 0) {
                botChecks['headlessChromeDetected'] = true;
                botChecks[_0x5a16('0x5c')] += 0x14;
                return;
            }
            
            // DO NOT CHECK plugins.length or mimeTypes.length - many real browsers
            // have zero plugins in normal mode
        }
        
        // ตรวจสอบและตัดสินว่าเป็น bot หรือไม่
        function evaluateBotStatus(){
            // Safety check to ensure botChecks object is properly defined
            if (!botChecks) {
                return true; // If botChecks is undefined, assume human (more lenient)
            }
            
            // WebDriver is a very strong signal - but only block if we're very sure
            if(typeof botChecks[_0x5a16('0x5a')] !== 'undefined' && botChecks[_0x5a16('0x5a')] && 
               navigator.webdriver === true) { // Only if navigator.webdriver is explicitly true
                return false; // WebDriver detected
            }
            
            // Calculate suspicion score
            var suspiciousScore = 0;
            
            // Add from existing bot score
            if(typeof botChecks[_0x5a16('0x5c')] !== 'undefined') {
                suspiciousScore += botChecks[_0x5a16('0x5c')];
            }
            
            // Check for automation markers
            if(typeof botChecks[_0x5a16('0x5b')] !== 'undefined' && botChecks[_0x5a16('0x5b')]) {
                suspiciousScore += 15;
            }
            
            // Check for headless markers - lower weight
            if(typeof botChecks['headlessChromeDetected'] !== 'undefined' && botChecks['headlessChromeDetected']) {
                suspiciousScore += 10;
            }
            
            // Give MUCH more weight to user interaction as proof of real browser
            // This is critical for avoiding false positives
            var hasUserInteraction = false;
            if((typeof botChecks[_0x5a16('0x58')] !== 'undefined' && botChecks[_0x5a16('0x58')]) || 
               (typeof botChecks[_0x5a16('0x59')] !== 'undefined' && botChecks[_0x5a16('0x59')])) {
                hasUserInteraction = true;
                // Heavy reduction in score for user interaction
                suspiciousScore -= 25;
            }
            
            // Higher threshold - require more signals to block
            var threshold = hasUserInteraction ? 40 : 30;
            
            // Return true if score is below threshold (not a bot)
            return suspiciousScore < threshold;
        }
        
        // Execute challenge
        setTimeout(function(){
            try{
                // More lenient cookie check - only block if cookies are definitely disabled
                if(!areCookiesEnabled()){
                    document.querySelector('.message').textContent = 'Please enable cookies to continue.';
                    document.querySelector('.instructions').innerHTML = 
                        '❌<br>Cookies are required for this site to function properly.';
                    document.querySelector('.instructions').style.color = '#ff5555';
                    document.querySelector('.instructions').style.borderColor = '#ff5555';
                    document.querySelector('.instructions').style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                    return;
                }
                
                var botCheckResult = false;
                try {
                    botCheckResult = evaluateBotStatus();
                    // More detailed logging
                    console.log("Bot score:", botChecks.botScore || 0);
                    console.log("Bot detection details:", JSON.stringify({
                        webdriver: botChecks.webdriverDetected || false,
                        headless: botChecks.headlessChromeDetected || false,
                        automation: botChecks.automationDetected || false,
                        interaction: botChecks.userInteraction || false,
                        mouseDetected: botChecks.mouseDetected || false,
                        features: botChecks.featuresValid !== false,
                        missingFeatures: botChecks.missingFeatures || []
                    }));
                } catch (err) {
                    console.error("Bot check error:", err);
                    // If evaluation fails, default to passing the check
                    botCheckResult = true;
                }
                
                if(!botCheckResult){
                    document.querySelector('.message').textContent = 
                        'Access denied. This website does not allow automated access.';
                    
                    if (botChecks.webdriverDetected) {
                        document.querySelector('.instructions').innerHTML = 
                            '❌<br>WebDriver detected. Automated browsing is not allowed.';
                        document.querySelector('.instructions').style.color = '#ff5555';
                        document.querySelector('.instructions').style.borderColor = '#ff5555';
                        document.querySelector('.instructions').style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                    } else if (botChecks.headlessChromeDetected) {
                        document.querySelector('.instructions').innerHTML = 
                            '❌<br>Headless Chrome detected. Automated browsing is not allowed.';
                        document.querySelector('.instructions').style.color = '#ff5555';
                        document.querySelector('.instructions').style.borderColor = '#ff5555';
                        document.querySelector('.instructions').style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                    } else if (!botChecks.featuresValid) {
                        document.querySelector('.instructions').innerHTML = 
                            '❌<br>Browser feature check failed. Missing: ' + (botChecks.missingFeatures || []).slice(0, 2).join(', ');
                        document.querySelector('.instructions').style.color = '#ff5555';
                        document.querySelector('.instructions').style.borderColor = '#ff5555';
                        document.querySelector('.instructions').style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                    } else {
                        document.querySelector('.instructions').innerHTML = 
                            '❌<br>Automated access detected. Try using a standard browser.';
                        document.querySelector('.instructions').style.color = '#ff5555';
                        document.querySelector('.instructions').style.borderColor = '#ff5555';
                        document.querySelector('.instructions').style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                    }
                    return;
                }
            
                document.querySelector('.message').textContent = 'Verification successful, please wait...';
                try {
                    sendVerificationToPHP(function() {
                        // Reload after PHP sets the cookie
                        window.location.reload();
                    });
                } catch (e) {
                    console.error("Verification error:", e);
                    document.querySelector('.message').textContent = 
                        'An error occurred during verification. Please refresh the page and try again.';
                }
            } catch (e) {
                console.error("Verification error:", e);
                // More user-friendly error message that doesn't suggest browser change
                document.querySelector('.message').textContent = 
                    'An error occurred during verification. Please refresh the page and try again.';
            }
        }, 2000); // Reduced timeout for better user experience
        })();
    </script>
</body>
</html>`, challengeID, challengeID, challengeID)
    
    ctx.SetStatusCode(fasthttp.StatusOK)
    ctx.SetContentType("text/html; charset=utf-8")
    ctx.SetBodyString(jsChallengePage)
}

// handleCachedContent serves content from the cache or fetches it from the source URL if needed
func handleCachedContent(ctx *fasthttp.RequestCtx, protection *Protection, cacheKey string, sourceURL string) {
    // Check if user has a valid cache cookie
    cookieName := "cached_content_" + cacheKey
    cookie := string(ctx.Request.Header.Cookie(cookieName))
    
    // Try to get content from cache
    cachedContent, err := protection.ContentCache.GetContent(cacheKey, sourceURL)
    
    // Handle errors when fetching content
    if err != nil {
        // Check if there's a fallback custom HTML file
        fallbackPath := "cdn.html"
        if _, fileErr := os.Stat(fallbackPath); fileErr == nil {
            // Custom fallback HTML file exists, serve it
            content, readErr := os.ReadFile(fallbackPath)
            if readErr == nil {
                ctx.SetContentType("text/html; charset=utf-8")
                ctx.SetBody(content)
                return
            }
        }
        
        // Use built-in fallback HTML
        ctx.SetContentType("text/html; charset=utf-8")
        ctx.SetBody([]byte(fallbackHTML))
        
        // Add error details in header for debugging
        ctx.Response.Header.Set("X-Cache-Error", fmt.Sprintf("%v", err))
        return
    }
    
    // Set cookie if not present or invalid
    if cookie == "" || !protection.ContentCache.ValidateCookie(cacheKey, cookie) {
        cookie := fasthttp.AcquireCookie()
        defer fasthttp.ReleaseCookie(cookie)
        
        cookie.SetKey(cookieName)
        cookie.SetValue(cachedContent.CookieVal)
        cookie.SetExpire(cachedContent.ExpiresAt)
        cookie.SetHTTPOnly(true)
        cookie.SetSameSite(fasthttp.CookieSameSiteStrictMode)
        
        ctx.Response.Header.SetCookie(cookie)
    }
    
    // Set appropriate headers
    ctx.SetContentType(cachedContent.ContentType)
    ctx.Response.Header.Set("X-Cache", "HIT")
    ctx.Response.Header.Set("X-Cache-Expires", cachedContent.ExpiresAt.Format(time.RFC1123))
    ctx.Response.Header.Set("Cache-Control", fmt.Sprintf("max-age=%d", int(cachedContent.ExpiresAt.Sub(time.Now()).Seconds())))
    
    // Serve the content
    ctx.SetBody(cachedContent.Content)
}

func handleRequest(ctx *fasthttp.RequestCtx, protection *Protection) {
    path := string(ctx.Path())
    ipAddr := ctx.RemoteIP().String()
    userAgent := string(ctx.UserAgent())
    
    // Check explicitly excluded paths
    excludedPaths := []string{"/favicon.ico", "/set_cookie.php"}
    isExcludedPath := false
    
    for _, excludedPath := range excludedPaths {
        if path == excludedPath || strings.HasPrefix(path, excludedPath) {
            isExcludedPath = true
            break
        }
    }
    
    // Handle cookie-setting endpoint
    if path == "/set_cookie.php" {
        // Process POST request to set cookie
        if string(ctx.Method()) == "POST" {
            // Extract path from form values
            reqPath := string(ctx.FormValue("path"))
            if reqPath == "" {
                reqPath = "/"
            }
            
            // Generate cookie
            cookieValue := protection.CookieProtection.GenerateCookie()
            
            // Set cookie with path
            cookie := fasthttp.AcquireCookie()
            defer fasthttp.ReleaseCookie(cookie)
            
            cookie.SetKey(COOKIE_NAME)
            cookie.SetValue(cookieValue)
            cookie.SetExpire(time.Now().Add(COOKIE_LIFETIME))
            cookie.SetHTTPOnly(true)
            cookie.SetPath(reqPath)
            
            ctx.Response.Header.SetCookie(cookie)
            
            // Set root cookie as well for broader access
            rootCookie := fasthttp.AcquireCookie()
            defer fasthttp.ReleaseCookie(rootCookie)
            
            rootCookie.SetKey(COOKIE_NAME + "_root")
            rootCookie.SetValue(cookieValue)
            rootCookie.SetExpire(time.Now().Add(COOKIE_LIFETIME))
            rootCookie.SetHTTPOnly(true)
            rootCookie.SetPath("/")
            
            ctx.Response.Header.SetCookie(rootCookie)
            
            // Return success
            ctx.SetContentType("application/json")
            ctx.SetStatusCode(fasthttp.StatusOK)
            ctx.SetBodyString(`{"success":true}`)
        } else {
            // Set CORS headers for preflight requests
            ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
            ctx.Response.Header.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
            ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type")
            
            if string(ctx.Method()) == "OPTIONS" {
                ctx.SetStatusCode(fasthttp.StatusOK)
            } else {
                ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
            }
        }
        return
    }
    
    // Check for valid cookie
    cookie := string(ctx.Request.Header.Cookie(COOKIE_NAME))
    rootCookie := string(ctx.Request.Header.Cookie(COOKIE_NAME + "_root"))
    
    validCookie := (cookie != "" && protection.CookieProtection.ValidateCookie(cookie)) || 
                  (rootCookie != "" && protection.CookieProtection.ValidateCookie(rootCookie))
    
    // If no valid cookie, show JS challenge
    if !validCookie && !isExcludedPath {
            showJSChallenger(ctx, protection, path, ipAddr, userAgent)
            return
        }
        
    // If we get here, either the path is excluded or the user has a valid cookie
    // Serve the actual content
    
    // First check if it's a static file
    staticFile := false
    
    if strings.HasSuffix(path, ".css") || 
       strings.HasSuffix(path, ".js") || 
       strings.HasSuffix(path, ".jpg") || 
       strings.HasSuffix(path, ".png") || 
       strings.HasSuffix(path, ".gif") ||
       strings.HasSuffix(path, ".ico") {
        staticFile = true
    }
    
    if staticFile {
        // Serve static file if it exists
        filePath := "static" + path
        if _, err := os.Stat(filePath); err == nil {
            ctx.SendFile(filePath)
            return
        }
    }
    
    // Default behavior: serve cached or dynamic content
    // First try to load content from cache with the path as key
    if path == "/" {
        handleCachedContent(ctx, protection, "index", "https://fn4tichz.net/")
    } else {
        // Convert path to a valid cache key by removing slashes and file extensions
        cacheKey := strings.Trim(path, "/")
        if cacheKey == "" {
            cacheKey = "index"
        }
        
        // Use the path to create the source URL
        sourceURL := "https://fn4tichz.net" + path
        
        handleCachedContent(ctx, protection, cacheKey, sourceURL)
    }
}

func isValidUserAgent(ua string) bool {
    ua = strings.ToLower(ua)
    
    // Block empty UA
    if ua == "" {
        return false
    }

    // Block common bot/crawler UAs
    blockedUA := []string{
        "bot", "crawler", "spider", "http", "curl", "wget",
        "python", "ruby", "perl", "phantomjs", "headless",
    }

    for _, blocked := range blockedUA {
        if strings.Contains(ua, blocked) {
            // Allow major search engines
            if strings.Contains(ua, "googlebot") ||
               strings.Contains(ua, "bingbot") ||
               strings.Contains(ua, "yandexbot") {
                return true
            }
            return false
        }
    }

    return true
}

// Helper functions
func containsUint16(slice []uint16, item uint16) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func containsCurveID(slice []tls.CurveID, item tls.CurveID) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

// Constants for fallback HTML
const fallbackHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Content Delivery</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-top: 0;
        }
        .content {
            background-color: white;
            padding: 20px;
            border-radius: 4px;
            margin-top: 20px;
        }
        .loading {
            text-align: center;
            padding: 40px;
            font-size: 18px;
        }
        .status {
            margin-top: 20px;
            padding: 10px;
            background-color: #e7f5fe;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Content Delivery System</h1>
        <div class="content">
            <p>The requested content is being retrieved or processed.</p>
            <div class="loading">Loading content...</div>
            <div class="status">
                Status: Fetching content from source
            </div>
        </div>
    </div>
</body>
</html>`

// Added for the new cleanupExpiredAttempts function
func (t *TLSHandshakeProtection) cleanupExpiredAttempts() {
    t.Lock()
    defer t.Unlock()
    
    now := time.Now()
    // Loop through the attempts map and remove entries older than 30 minutes
    for ip, attempt := range t.attempts {
        if !attempt.blocked && now.Sub(attempt.lastTry) > 30*time.Minute {
            delete(t.attempts, ip)
        }
    }
}
