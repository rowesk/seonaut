package crawler

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Method int

const (
	// Supported HTTP methods.
	GET Method = iota
	HEAD

	// Random delay in milliseconds.
	// A random delay up to this value is introduced before new HTTP requests.
	randomDelay = 1500

	// Number of threads a queue will use to crawl a project.
	consumerThreads = 2

	// Crawler timeout in hours.
	crawlerTimeout = 2
)

var ErrBlockedByRobotstxt = errors.New("blocked by robots.txt")
var ErrVisited = errors.New("URL already visited")
var ErrDomainNotAllowed = errors.New("domain not allowed")

type Client interface {
	Get(urlStr string) (*ClientResponse, error)
	Head(urlStr string) (*ClientResponse, error)
	GetUAName() string
}

type ResponseCallback func(r *ResponseMessage)

type Options struct {
	CrawlLimit      int
	IgnoreRobotsTxt bool
	FollowNofollow  bool
	IncludeNoindex  bool
	CrawlSitemap    bool
	AllowSubdomains bool
    RateLimit       int
}

type Status struct {
	Crawled    int
	Crawling   bool
	Discovered int
}

// rateLimitState tracks rate limiting status per domain
type rateLimitState struct {
	backoffUntil        time.Time
	consecutiveFailures int
	lastBackoff         time.Duration
}

type Crawler struct {
	Client           Client
	status           Status
	url              *url.URL
	options          *Options
	queue            *Queue
	storage          *URLStorage
	sitemapStorage   *URLStorage
	sitemapChecker   *SitemapChecker
	sitemapExists    bool
	sitemapIsBlocked bool
	sitemaps         []string
	robotsChecker    *RobotsChecker
	allowedDomains   map[string]bool
	mainDomain       string
	cancel           context.CancelFunc
	context          context.Context
	callback         ResponseCallback
	rateGate         <-chan time.Time
	rateLimitStates  map[string]*rateLimitState
	rateLimitMutex   sync.RWMutex
}

type ClientResponse struct {
	Response *http.Response
	TTFB     int
}

type RequestMessage struct {
	URL          *url.URL
	IgnoreDomain bool
	Method       Method
	Data         interface{}
}

type ResponseMessage struct {
	URL       *url.URL
	Response  *http.Response
	Error     error
	TTFB      int
	Blocked   bool
	InSitemap bool
	Timeout   bool
	Data      interface{}
}

func NewCrawler(parsedURL *url.URL, options *Options, client Client) *Crawler {
	mainDomain := strings.TrimPrefix(parsedURL.Host, "www.")

	robotsChecker := NewRobotsChecker(client)
	sitemapChecker := NewSitemapChecker(client, options.CrawlLimit)

	ctx, cancel := context.WithTimeout(context.Background(), crawlerTimeout*time.Hour)

	c := &Crawler{
		Client:          client,
		status:          Status{Crawling: true},
		url:             parsedURL,
		options:         options,
		queue:           NewQueue(),
		storage:         NewURLStorage(),
		sitemapStorage:  NewURLStorage(),
		sitemapChecker:  sitemapChecker,
		robotsChecker:   robotsChecker,
		allowedDomains:  map[string]bool{mainDomain: true, "www." + mainDomain: true},
		mainDomain:      mainDomain,
		cancel:          cancel,
		context:         ctx,
		rateLimitStates: make(map[string]*rateLimitState),
	}

    if options.RateLimit > 0 {
        // Token-like gate. time.Tick is acceptable here since crawler lifetime is bounded.
        interval := time.Second / time.Duration(options.RateLimit)
        if interval <= 0 {
            interval = time.Second
        }
        c.rateGate = time.Tick(interval)
    }

    return c
}

// OnResponse sets the callback that the crawler will call for every response.
func (c *Crawler) OnResponse(r ResponseCallback) {
	c.callback = r
}

// Crawl starts crawling an URL and sends pagereports of the crawled URLs
// through the pr channel. It will end when there are no more URLs to crawl
// or the MaxPageReports limit is hit.
func (c *Crawler) Start() {
	defer c.queue.Done()
	defer c.cancel() // cancel the consumers so all channels are closed.

	c.setupSitemaps()

	if c.sitemapExists && c.options.CrawlSitemap {
		c.sitemapChecker.ParseSitemaps(c.sitemaps, c.loadSitemapURLs)
	}

	sitemapLoaded := false
	if !c.queue.Active() && c.options.CrawlSitemap {
		c.queueSitemapURLs()
		sitemapLoaded = true
	}

	if !c.queue.Active() {
		return
	}

	for rm := range c.crawl() {
		c.queue.Ack(rm.URL.String())

		rm.InSitemap = c.sitemapStorage.Seen(rm.URL.String())
		rm.Blocked = c.robotsChecker.IsBlocked(rm.URL)
		rm.Timeout = rm.Error != nil

		c.status.Crawled++

		if c.callback != nil {
			c.callback(rm)
		}

		if !c.queue.Active() && c.options.CrawlSitemap && !sitemapLoaded {
			c.queueSitemapURLs()
			sitemapLoaded = true
		}

		if !c.queue.Active() || c.status.Crawled >= c.options.CrawlLimit {
			break
		}
	}
}

// AddRequest processes a request message for the crawler.
// It checks if the URL has already been visited, validates the domain and checks
// if it is blocked in the the robots.txt rules. It returns an error if any of the checks
// fails. Finally, it adds the request to the processing queue.
func (c *Crawler) AddRequest(r *RequestMessage) error {
	if c.storage.Seen(r.URL.String()) {
		return ErrVisited
	}

	c.storage.Add(r.URL.String())

	if !c.domainIsAllowed(r.URL.Host) && !r.IgnoreDomain {
		return ErrDomainNotAllowed
	}

	if !c.options.IgnoreRobotsTxt && c.robotsChecker.IsBlocked(r.URL) {
		return ErrBlockedByRobotstxt
	}

	c.queue.Push(r)

	return nil
}

// GetStatus returns the current cralwer status.
func (c *Crawler) GetStatus() Status {
	c.status.Discovered = c.queue.Count()
	c.status.Crawling = c.context.Err() == nil

	return c.status
}

// Returns true if the sitemap.xml file exists.
func (c *Crawler) SitemapExists() bool {
	return c.sitemapExists
}

// Returns true if the robots.txt file exists.
func (c *Crawler) RobotstxtExists() bool {
	return c.robotsChecker.Exists(c.url)
}

// Returns true if any of the website's sitemaps is blocked in the robots.txt file.
func (c *Crawler) SitemapIsBlocked() bool {
	return c.sitemapIsBlocked
}

// Stops the cralwer by canceling the cralwer context.
func (c *Crawler) Stop() {
	c.cancel()
}

// setupSitemaps checks if any sitemap exists for the crawler's url. It checks the robots file
// as well as the default sitemap location. Afterwards it checks if the sitemap files are blocked
// by the robots file. Any non-blocked sitemap is added to the crawler's sitemaps slice so it can
// be loaded later on.
func (c *Crawler) setupSitemaps() {
	sitemaps := c.robotsChecker.GetSitemaps(c.url)
	nonBlockedSitemaps := []string{}
	if len(sitemaps) == 0 {
		sitemaps = []string{c.url.Scheme + "://" + c.url.Host + "/sitemap.xml"}
	}

	for _, sm := range sitemaps {
		parsedSm, err := url.Parse(sm)
		if err != nil {
			continue
		}

		if c.robotsChecker.IsBlocked(parsedSm) {
			c.sitemapIsBlocked = true
			if !c.options.IgnoreRobotsTxt {
				continue
			}
		}

		nonBlockedSitemaps = append(nonBlockedSitemaps, sm)
	}

	c.sitemaps = nonBlockedSitemaps
	c.sitemapExists = c.sitemapChecker.SitemapExists(sitemaps)
}

// crawl starts the request consumers in goroutines and polls URLs from the queue so they
// can be requested concurrently.
func (c *Crawler) crawl() <-chan *ResponseMessage {
	reqStream := make(chan *RequestMessage)
	respStream := make(chan *ResponseMessage)

	wg := new(sync.WaitGroup)
	wg.Add(consumerThreads)

	// Starts the consumers that will make the client requests
	for i := 0; i < consumerThreads; i++ {
		go func() {
			defer wg.Done()
			c.consumer(reqStream, respStream)
		}()
	}

	// Polls URLs from the queue and send them to the requests stream so they can
	// be consumed. Waits for all the consumers to finish before closing the channels.
	go func() {
		defer close(reqStream)
		defer close(respStream)
		defer wg.Wait()

		for {
			select {
			case <-c.context.Done():
				return
			case reqStream <- c.queue.Poll():
			}
		}
	}()

	return respStream
}

// Consumer gets URLs from the reqStream until the context is cancelled.
// It adds a random delay between client calls.
func (c *Crawler) consumer(reqStream <-chan *RequestMessage, respStream chan<- *ResponseMessage) {
	for {
		select {
		case requestMessage := <-reqStream:
			domain := requestMessage.URL.Host

			// Check if this domain is currently rate-limited
			if backoffDuration := c.isDomainRateLimited(domain); backoffDuration > 0 {
				log.Printf("Domain %s is rate-limited, requeuing request for %s (backoff: %v)", domain, requestMessage.URL.String(), backoffDuration)
				// Push back to queue to try later
				c.scheduleRetry(requestMessage, backoffDuration)
				continue
			}

            // Rate gate first, if enabled
            if c.rateGate != nil {
                <-c.rateGate
            }
            // Add random delay to avoid overwhelming the servers with requests.
            jitter := randomDelay
            if c.rateGate != nil {
                // Reduce jitter when explicit rate limiting is enabled
                jitter = randomDelay / 3
                if jitter < 50 { jitter = 50 }
            }
            time.Sleep(time.Duration(rand.Intn(jitter)) * time.Millisecond)

			rm := &ResponseMessage{
				URL:  requestMessage.URL,
				Data: requestMessage.Data,
			}

			r := &ClientResponse{}
			switch requestMessage.Method {
			case GET:
				r, rm.Error = c.Client.Get(requestMessage.URL.String())
			case HEAD:
				r, rm.Error = c.Client.Head(requestMessage.URL.String())
			}

            if rm.Error == nil {
				rm.Response = r.Response
				rm.TTFB = r.TTFB
                // Enhanced rate limiting detection and Retry-After handling
                if rm.Response != nil {
                    if c.shouldRetryWithBackoff(rm.Response) {
                        log.Printf("Rate limiting detected for %s (status: %d)", requestMessage.URL.String(), rm.Response.StatusCode)
                        
                        // Determine backoff duration
                        var backoff time.Duration
                        if d := parseRetryAfter(rm.Response.Header.Get("Retry-After")); d > 0 {
                            log.Printf("Using Retry-After header: %v", d)
                            backoff = d
                        } else {
                            backoff = c.getDefaultBackoff(rm.Response)
                            log.Printf("Using default backoff: %v", backoff)
                        }
                        
                        // Mark domain as rate-limited with exponential backoff
                        backoff = c.markDomainRateLimited(domain, backoff)
                        log.Printf("Domain %s marked as rate-limited for %v", domain, backoff)
                        
                        // Schedule retry for this specific request
                        c.scheduleRetry(requestMessage, backoff)
                    } else {
                        // Successful response - clear rate limit for domain
                        c.clearDomainRateLimit(domain)
                    }
                }
			}

			respStream <- rm
		case <-c.context.Done():
			return
		}
	}
}

// Callback to load sitemap URLs into the sitemap storage.
func (c *Crawler) loadSitemapURLs(u string) {
	l, err := url.Parse(u)
	if err != nil {
		return
	}

	if l.Path == "" {
		l.Path = "/"
	}

	c.sitemapStorage.Add(l.String())
}

// queueSitemapURLs loops through the sitemap's URLs, adding any unseen URLs to the crawler's queue.
func (c *Crawler) queueSitemapURLs() {
	c.sitemapStorage.Iterate(func(v string) {
		if !c.storage.Seen(v) {
			c.storage.Add(v)
			u, err := url.Parse(v)
			if err != nil {
				return
			}

			c.queue.Push(&RequestMessage{URL: u})
		}
	})
}

// parseRetryAfter parses an HTTP Retry-After header which can be seconds or an HTTP-date.
func parseRetryAfter(v string) time.Duration {
    if v == "" {
        return 0
    }
    if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
        return time.Duration(secs) * time.Second
    }
    if t, err := http.ParseTime(v); err == nil {
        d := time.Until(t)
        if d < 0 {
            return 0
        }
        return d
    }
    return 0
}

// shouldRetryWithBackoff detects if a response indicates rate limiting or temporary blocking.
func (c *Crawler) shouldRetryWithBackoff(resp *http.Response) bool {
    // Standard 429 Too Many Requests
    if resp.StatusCode == http.StatusTooManyRequests {
        return true
    }

    // 503 Service Unavailable (often used for rate limiting)
    if resp.StatusCode == http.StatusServiceUnavailable {
        return true
    }

    // Cloudflare challenge detection
    if c.isCloudflareChallenge(resp) {
        return true
    }

    // Check for rate limiting headers even on non-429 responses
    rateLimitHeaders := []string{
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
    }

    for _, header := range rateLimitHeaders {
        if resp.Header.Get(header) != "" {
            return true
        }
    }

    return false
}

// isCloudflareChallenge detects Cloudflare challenge pages that indicate rate limiting.
func (c *Crawler) isCloudflareChallenge(resp *http.Response) bool {
    // Check for Cloudflare challenge indicators
    if resp.Header.Get("Server") == "cloudflare" {
        // Server-Timing header with challenge indicator (more flexible matching)
        serverTiming := strings.ToLower(resp.Header.Get("Server-Timing"))
        if strings.Contains(serverTiming, "chlray") || strings.Contains(serverTiming, "challenge") {
            return true
        }

        // Cf-Mitigated header indicating challenge
        cfMitigated := strings.ToLower(resp.Header.Get("Cf-Mitigated"))
        if strings.Contains(cfMitigated, "challenge") {
            return true
        }

        // CF-Ray header indicates Cloudflare is in the path
        if resp.Header.Get("CF-Ray") != "" && resp.StatusCode == http.StatusForbidden {
            return true
        }

        // Check for common challenge page indicators in title or meta
        // This is a fallback for cases where headers aren't clear
        if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
            contentType := strings.ToLower(resp.Header.Get("Content-Type"))
            if strings.Contains(contentType, "text/html") {
                // Additional check could be added here for HTML content analysis
                // but for now, rely on the headers which are more reliable
            }
        }
    }

    return false
}

// getDefaultBackoff returns appropriate backoff duration based on response type.
func (c *Crawler) getDefaultBackoff(resp *http.Response) time.Duration {
    // Longer backoff for Cloudflare challenges
    if c.isCloudflareChallenge(resp) {
        return time.Duration(5+rand.Intn(10)) * time.Second
    }

    // Standard 429 or 503 responses
    if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
        return time.Duration(2+rand.Intn(3)) * time.Second
    }

    // Default conservative backoff
    return time.Duration(1+rand.Intn(2)) * time.Second
}

// isDomainRateLimited checks if a domain is currently in backoff period.
// Returns the remaining backoff duration, or 0 if not rate-limited.
func (c *Crawler) isDomainRateLimited(domain string) time.Duration {
    c.rateLimitMutex.RLock()
    defer c.rateLimitMutex.RUnlock()
    
    if state, exists := c.rateLimitStates[domain]; exists {
        remaining := time.Until(state.backoffUntil)
        if remaining > 0 {
            return remaining
        }
    }
    return 0
}

// markDomainRateLimited marks a domain as rate-limited with exponential backoff.
// Returns the actual backoff duration being applied (may be longer than requested due to exponential backoff).
func (c *Crawler) markDomainRateLimited(domain string, baseBackoff time.Duration) time.Duration {
    c.rateLimitMutex.Lock()
    defer c.rateLimitMutex.Unlock()
    
    state, exists := c.rateLimitStates[domain]
    if !exists {
        state = &rateLimitState{}
        c.rateLimitStates[domain] = state
    }
    
    // Increment consecutive failures
    state.consecutiveFailures++
    
    // Apply exponential backoff: each failure adds 2s, up to a max of 60s
    actualBackoff := baseBackoff
    if state.consecutiveFailures > 1 {
        // Exponential increase: add 2s per additional failure
        additionalBackoff := time.Duration(state.consecutiveFailures-1) * 2 * time.Second
        actualBackoff = baseBackoff + additionalBackoff
        
        // Cap at 60 seconds
        if actualBackoff > 60*time.Second {
            actualBackoff = 60 * time.Second
        }
        
        log.Printf("Domain %s has %d consecutive failures, increasing backoff from %v to %v", 
            domain, state.consecutiveFailures, baseBackoff, actualBackoff)
    }
    
    state.backoffUntil = time.Now().Add(actualBackoff)
    state.lastBackoff = actualBackoff
    
    return actualBackoff
}

// clearDomainRateLimit clears the rate limit state for a domain after a successful request.
func (c *Crawler) clearDomainRateLimit(domain string) {
    c.rateLimitMutex.Lock()
    defer c.rateLimitMutex.Unlock()
    
    if state, exists := c.rateLimitStates[domain]; exists && state.consecutiveFailures > 0 {
        log.Printf("Domain %s rate limit cleared after successful request (was: %d failures)", 
            domain, state.consecutiveFailures)
        delete(c.rateLimitStates, domain)
    }
}

// scheduleRetry re-enqueues a request after a delay without marking it visited again.
func (c *Crawler) scheduleRetry(req *RequestMessage, d time.Duration) {
    // Use a new RequestMessage to avoid races; keep Method/Data
    rcopy := &RequestMessage{URL: req.URL, IgnoreDomain: req.IgnoreDomain, Method: req.Method, Data: req.Data}
    time.AfterFunc(d, func() {
        // Push directly to queue, as URL has been marked seen already
        select {
        case <-c.context.Done():
            return
        default:
            log.Printf("Retrying %s after %v backoff", req.URL.String(), d)
            c.queue.Push(rcopy)
        }
    })
}

// Returns true if the crawler is allowed to crawl the domain, checking the allowedDomains slice.
// If the AllowSubdomains option is set, returns true the given domain is a subdomain of the
// crawlers's base domain.
func (c *Crawler) domainIsAllowed(d string) bool {
	_, ok := c.allowedDomains[d]
	if ok {
		return true
	}

	if c.options.AllowSubdomains && strings.HasSuffix(d, c.mainDomain) {
		return true
	}

	return false
}
