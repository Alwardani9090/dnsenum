package dnsprobe

import (
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Alwardani9090/dnsenum/pkg/client"
	"github.com/cyinnove/tldify"
	"github.com/miekg/dns"
)

const (
	wildcardProbeCount      = 5
	wildcardThreshold       = 5
	maxDeepResolverAttempts = 3
)

var (
	dnsQuery          = client.Query
	randomLabel       = generateRandomLabel
	wildcardQTypes    = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME}
	wildcardRecordSet = map[string]struct{}{
		"A":     {},
		"AAAA":  {},
		"CNAME": {},
	}
)

type ProbeResult struct {
	Host             string
	Results          []*client.Result
	Wildcard         bool
	ResolversChecked int
}

type wildcardBaseline struct {
	detected bool
	values   map[string]struct{}
}

type probedHost struct {
	result         *ProbeResult
	fingerprint    string
	wildcardValues map[string]struct{}
	levels         []string
}

func (p probedHost) isWildcardCandidate() bool {
	return p.result != nil && len(p.result.Results) > 0 && p.fingerprint != "" && len(p.levels) > 0
}

type thresholdTracker struct {
	mu     sync.Mutex
	counts map[string]int
}

func newThresholdTracker() *thresholdTracker {
	return &thresholdTracker{
		counts: make(map[string]int),
	}
}

func (t *thresholdTracker) add(level, fingerprint string) {
	if level == "" || fingerprint == "" {
		return
	}
	key := thresholdKey(level, fingerprint)
	t.mu.Lock()
	t.counts[key]++
	t.mu.Unlock()
}

func (t *thresholdTracker) overThreshold() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]string, 0, len(t.counts))
	for key, count := range t.counts {
		if count >= wildcardThreshold {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

type batchProber struct {
	timeout     int
	records     []uint16
	resolvers   []string
	strategy    string
	concurrency int

	resolverSeq uint64

	wildcardMu sync.Mutex
	wildcards  map[string]wildcardBaseline
}

func RunProbe(timeout int, host string, records []uint16, resolvers []string, strategy string) *ProbeResult {
	prober := newBatchProber(timeout, records, resolvers, strategy, 1)
	probe := prober.probeHost(host)
	if probe.result == nil {
		return &ProbeResult{Host: host}
	}
	if probe.isWildcardCandidate() && prober.isDirectWildcardHit(probe) {
		probe.result.Wildcard = true
		probe.result.Results = nil
	}
	return probe.result
}

func RunBatch(timeout int, hosts []string, records []uint16, resolvers []string, strategy string, concurrency int, onProgress func(done, total int)) []*ProbeResult {
	prober := newBatchProber(timeout, records, resolvers, strategy, concurrency)
	return prober.run(hosts, onProgress)
}

func newBatchProber(timeout int, records []uint16, resolvers []string, strategy string, concurrency int) *batchProber {
	if timeout < 1 {
		timeout = 5
	}
	if len(records) == 0 {
		records = []uint16{dns.TypeA}
	}
	if len(resolvers) == 0 {
		resolvers = append([]string(nil), client.DefaultResolvers...)
	} else {
		resolvers = append([]string(nil), resolvers...)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy == "" {
		strategy = "fast"
	}

	return &batchProber{
		timeout:     timeout,
		records:     append([]uint16(nil), records...),
		resolvers:   resolvers,
		strategy:    strategy,
		concurrency: concurrency,
		wildcards:   make(map[string]wildcardBaseline),
	}
}

func (p *batchProber) run(hosts []string, onProgress func(done, total int)) []*ProbeResult {
	if len(hosts) == 0 {
		return nil
	}

	type job struct {
		idx  int
		host string
	}
	type outcome struct {
		idx   int
		probe probedHost
	}

	jobs := make(chan job)
	outcomes := make(chan outcome, len(hosts))

	workers := p.concurrency
	if workers > len(hosts) {
		workers = len(hosts)
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				outcomes <- outcome{
					idx:   job.idx,
					probe: p.probeHost(job.host),
				}
			}
		}()
	}

	go func() {
		for idx, host := range hosts {
			jobs <- job{idx: idx, host: host}
		}
		close(jobs)
		wg.Wait()
		close(outcomes)
	}()

	probes := make([]probedHost, len(hosts))
	tracker := newThresholdTracker()
	done := 0
	for outcome := range outcomes {
		probes[outcome.idx] = outcome.probe
		done++
		if onProgress != nil {
			onProgress(done, len(hosts))
		}
		if !outcome.probe.isWildcardCandidate() {
			continue
		}
		for _, level := range outcome.probe.levels {
			tracker.add(level, outcome.probe.fingerprint)
		}
	}

	confirmed := make(map[string]bool)
	for _, key := range tracker.overThreshold() {
		level, fingerprint := splitThresholdKey(key)
		if level == "" || fingerprint == "" {
			continue
		}
		confirmed[key] = p.confirmThresholdWildcard(level, splitFingerprint(fingerprint))
	}

	results := make([]*ProbeResult, len(probes))
	for i, probe := range probes {
		if probe.result == nil {
			results[i] = &ProbeResult{Host: hosts[i]}
			continue
		}
		if probe.isWildcardCandidate() && p.matchesConfirmedWildcard(probe, confirmed) {
			probe.result.Wildcard = true
			probe.result.Results = nil
		}
		results[i] = probe.result
	}
	return results
}

func (p *batchProber) matchesConfirmedWildcard(probe probedHost, confirmed map[string]bool) bool {
	for _, level := range probe.levels {
		if confirmed[thresholdKey(level, probe.fingerprint)] {
			return true
		}
	}
	return false
}

func (p *batchProber) isDirectWildcardHit(probe probedHost) bool {
	for _, level := range probe.levels {
		baseline := p.getWildcardBaseline(level)
		if baseline.detected && probeMatchesBaseline(probe.wildcardValues, baseline) {
			return true
		}
	}
	return false
}

func (p *batchProber) confirmThresholdWildcard(level string, values map[string]struct{}) bool {
	baseline := p.getWildcardBaseline(level)
	return baseline.detected && probeMatchesBaseline(values, baseline)
}

func (p *batchProber) getWildcardBaseline(level string) wildcardBaseline {
	p.wildcardMu.Lock()
	if cached, ok := p.wildcards[level]; ok {
		p.wildcardMu.Unlock()
		return cached
	}
	p.wildcardMu.Unlock()

	baseline := wildcardBaseline{values: make(map[string]struct{})}
	for i := 0; i < wildcardProbeCount; i++ {
		values := p.probeWildcardValues(randomLabel() + "." + level)
		if len(values) == 0 {
			continue
		}
		baseline.detected = true
		for value := range values {
			baseline.values[value] = struct{}{}
		}
	}

	p.wildcardMu.Lock()
	if cached, ok := p.wildcards[level]; ok {
		p.wildcardMu.Unlock()
		return cached
	}
	p.wildcards[level] = baseline
	p.wildcardMu.Unlock()
	return baseline
}

func (p *batchProber) probeWildcardValues(host string) map[string]struct{} {
	results, _ := p.collectResults(host, wildcardQTypes)
	return wildcardValuesFromResults(results)
}

func (p *batchProber) probeHost(host string) probedHost {
	results, resolversChecked := p.collectResults(host, p.records)
	host = normalizeHost(host)

	probe := probedHost{
		result: &ProbeResult{
			Host:             host,
			Results:          results,
			ResolversChecked: resolversChecked,
		},
		wildcardValues: wildcardValuesFromResults(results),
	}

	if len(probe.wildcardValues) == 0 {
		return probe
	}

	root := registrableRoot(host)
	if root == "" || host == root {
		return probe
	}

	probe.fingerprint = joinSorted(probe.wildcardValues)
	probe.levels = wildcardLevels(host, root)
	return probe
}

func (p *batchProber) collectResults(host string, records []uint16) ([]*client.Result, int) {
	if len(records) == 0 || len(p.resolvers) == 0 {
		return nil, 0
	}

	aggregated := make(map[string]map[string]struct{})
	pending := append([]uint16(nil), records...)
	resolversChecked := 0
	for _, resolver := range p.pickResolvers(p.resolverAttempts()) {
		if len(pending) == 0 {
			break
		}
		resolversChecked++
		nextPending := pending[:0]
		for _, record := range pending {
			result, err := dnsQuery(host, p.timeout, record, resolver)
			if err != nil || !isUsableResult(result) {
				nextPending = append(nextPending, record)
				continue
			}
			mergeResult(aggregated, result)
		}
		pending = nextPending
		if p.strategy != "deep" {
			break
		}
	}

	return flattenResults(aggregated), resolversChecked
}

func (p *batchProber) resolverAttempts() int {
	if len(p.resolvers) == 0 {
		return 0
	}
	if p.strategy != "deep" {
		return 1
	}
	if len(p.resolvers) < maxDeepResolverAttempts {
		return len(p.resolvers)
	}
	return maxDeepResolverAttempts
}

func (p *batchProber) pickResolvers(limit int) []string {
	if limit <= 0 || len(p.resolvers) == 0 {
		return nil
	}
	if limit > len(p.resolvers) {
		limit = len(p.resolvers)
	}

	picked := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)
	for len(picked) < limit && len(seen) < len(p.resolvers) {
		resolver := p.nextResolver()
		if _, ok := seen[resolver]; ok {
			continue
		}
		seen[resolver] = struct{}{}
		picked = append(picked, resolver)
	}
	return picked
}

func (p *batchProber) nextResolver() string {
	if len(p.resolvers) == 1 {
		return p.resolvers[0]
	}
	idx := atomic.AddUint64(&p.resolverSeq, 1) - 1
	return p.resolvers[idx%uint64(len(p.resolvers))]
}

func mergeResult(dst map[string]map[string]struct{}, result *client.Result) {
	if result == nil {
		return
	}
	if _, ok := dst[result.RecordName]; !ok {
		dst[result.RecordName] = make(map[string]struct{})
	}
	for _, value := range result.Values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		dst[result.RecordName][value] = struct{}{}
	}
}

func flattenResults(aggregated map[string]map[string]struct{}) []*client.Result {
	if len(aggregated) == 0 {
		return nil
	}

	recordNames := make([]string, 0, len(aggregated))
	for recordName := range aggregated {
		recordNames = append(recordNames, recordName)
	}
	sort.Strings(recordNames)

	results := make([]*client.Result, 0, len(recordNames))
	for _, recordName := range recordNames {
		values := make([]string, 0, len(aggregated[recordName]))
		for value := range aggregated[recordName] {
			values = append(values, value)
		}
		sort.Strings(values)
		results = append(results, &client.Result{
			RecordName: recordName,
			DnsStatus:  "NOERROR",
			Values:     values,
		})
	}
	return results
}

func wildcardValuesFromResults(results []*client.Result) map[string]struct{} {
	values := make(map[string]struct{})
	for _, result := range results {
		if result == nil {
			continue
		}
		if _, ok := wildcardRecordSet[strings.ToUpper(result.RecordName)]; !ok {
			continue
		}
		for _, value := range result.Values {
			normalized := normalizeValue(value)
			if normalized != "" {
				values[normalized] = struct{}{}
			}
		}
	}
	return values
}

func probeMatchesBaseline(values map[string]struct{}, baseline wildcardBaseline) bool {
	if !baseline.detected || len(values) == 0 {
		return false
	}
	for value := range values {
		if _, ok := baseline.values[value]; !ok {
			return false
		}
	}
	return true
}

func wildcardLevels(host, root string) []string {
	host = normalizeHost(host)
	root = normalizeHost(root)

	var levels []string
	current := host
	for {
		dot := strings.IndexByte(current, '.')
		if dot < 0 {
			break
		}
		current = current[dot+1:]
		levels = append(levels, current)
		if current == root {
			break
		}
	}
	return levels
}

func registrableRoot(host string) string {
	host = normalizeHost(host)
	parsed, err := tldify.Parse(host)
	if err != nil || parsed.Domain == "" || parsed.TLD == "" {
		return ""
	}
	return normalizeHost(parsed.Domain + "." + parsed.TLD)
}

func thresholdKey(level, fingerprint string) string {
	return level + "\x00" + fingerprint
}

func splitThresholdKey(key string) (string, string) {
	level, fingerprint, ok := strings.Cut(key, "\x00")
	if !ok {
		return "", ""
	}
	return level, fingerprint
}

func splitFingerprint(fingerprint string) map[string]struct{} {
	values := make(map[string]struct{})
	if fingerprint == "" {
		return values
	}
	for _, part := range strings.Split(fingerprint, ",") {
		part = normalizeValue(part)
		if part != "" {
			values[part] = struct{}{}
		}
	}
	return values
}

func joinSorted(values map[string]struct{}) string {
	if len(values) == 0 {
		return ""
	}
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
}

func normalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
}

func isUsableResult(result *client.Result) bool {
	return result != nil && result.DnsStatus == "NOERROR" && len(result.Values) > 0
}

func generateRandomLabel() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, 20)
	for i := range buf {
		buf[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(buf)
}
