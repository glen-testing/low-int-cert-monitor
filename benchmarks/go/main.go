// Command p4inventory is a defensive weak-EC-key detector: given the
// public point(s) of X.509 certificates, it flags any whose private
// key is a trivially small integer d (Q = d*G), the eMudhra
// misissuance class. See common/spec.md for the full task spec.
package main

import (
	"flag"
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintln(os.Stderr, `p4inventory - weak EC key (small-d) detector

Usage:
  p4inventory bench --targets FILE --max N [--method linear|bsgs] [--n N] [--affine-n N]
  p4inventory selftest --targets FILE --answers FILE --max N
  p4inventory cert FILE [--max N]

bench with no --targets prints the ns/add microbenchmark table only.`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "bench":
		cmdBench(os.Args[2:])
	case "selftest":
		cmdSelftest(os.Args[2:])
	case "cert":
		cmdCert(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func cmdBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	targetsPath := fs.String("targets", "", "path to targets.tsv (optional; omit to only print the ns/add microbenchmark table)")
	max := fs.Uint64("max", 1_000_000, "sweep up to d<=max for the real-targets sweep")
	method := fs.String("method", "bsgs", "linear|bsgs for the real-targets sweep")
	n := fs.Int("n", 5_000_000, "number of adds for the jacobian/nistec/stdlib microbenchmarks")
	affineN := fs.Int("affine-n", 200_000, "number of adds for the slow affine+modinverse baseline microbenchmark")
	fs.Parse(args)

	RunMicrobench(*n, *affineN)

	if *targetsPath != "" {
		if err := RunSweepBench(*targetsPath, *max, *method); err != nil {
			fmt.Fprintln(os.Stderr, "bench: "+err.Error())
			os.Exit(1)
		}
	}
}

func cmdSelftest(args []string) {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	targetsPath := fs.String("targets", "", "path to targets.tsv")
	answersPath := fs.String("answers", "", "path to answers.tsv")
	max := fs.Uint64("max", 100_000_000, "sweep up to d<=max")
	fs.Parse(args)

	if *targetsPath == "" || *answersPath == "" {
		fmt.Fprintln(os.Stderr, "selftest: --targets and --answers are required")
		os.Exit(2)
	}
	if err := RunSelftest(*targetsPath, *answersPath, *max); err != nil {
		fmt.Fprintln(os.Stderr, "selftest: "+err.Error())
		os.Exit(1)
	}
}

func cmdCert(args []string) {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	max := fs.Uint64("max", 100_000_000, "sweep up to d<=max")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "cert: usage: p4inventory cert FILE [--max N]")
		os.Exit(2)
	}
	if err := RunCert(fs.Arg(0), *max); err != nil {
		fmt.Fprintln(os.Stderr, "cert: "+err.Error())
		os.Exit(1)
	}
}
