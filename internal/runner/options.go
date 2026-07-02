package runner

type Options struct {
	Targets             []string
	TargetsFile         string
	CustomResolverslist string
	CustomResolvers     []string
	Records             []string
	Strategy            string
	OutputFile          string
	Timeout             int
	Concurrency         int
	Silent              bool
}
