package runner

import (
	"fmt"
	"os"

	"github.com/Alwardani9090/dnsenum/internal/progress"
	"github.com/Alwardani9090/dnsenum/pkg/utils"

	"github.com/Alwardani9090/dnsenum/internal/log"
	"github.com/Alwardani9090/dnsenum/pkg/dnsprobe"
)

func Run(opts *Options) error {
	if opts.TargetsFile != "" {
		var err error
		opts.Targets, err = utils.ReadInputFromFile(opts.TargetsFile)
		if err != nil {
			log.Fatalf("failde to read targets file: %v", err)
		}
	}

	if utils.IsStdin() {
		var err error
		opts.Targets, err = utils.ReadInputFromStdin()
		if err != nil {
			log.Fatalf("faild to read targets file: %v", err)
		}
	}

	if len(opts.Targets) == 0 {
		log.Fatalf("no targets specified")
	}

	if opts.CustomResolverslist != "" {
		var err error
		opts.CustomResolvers, err = utils.ReadInputFromFile(opts.CustomResolverslist)
		if err != nil {
			log.Fatalf("faild to read custom resolvers list: %v", err)
		}
	}

	records := convertRecordsToUint16(opts.Records)
	progress.WriteToolProgress(os.Stderr, 0, len(opts.Targets), "dns-probe")
	results := dnsprobe.RunBatch(opts.Timeout, opts.Targets, records, opts.CustomResolvers, opts.Strategy, opts.Concurrency, func(done, total int) {
		progress.WriteToolProgress(os.Stderr, done, total, "dns-probe")
	})

	for _, result := range results {
		if result == nil || len(result.Results) == 0 {
			continue
		}
		fmt.Println(result.Host)
	}
	if opts.OutputFile != "" {
		if err := writeJSONOutput(opts.OutputFile, results); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		log.Infof("Results written to %s", opts.OutputFile)
	}

	return nil
}
