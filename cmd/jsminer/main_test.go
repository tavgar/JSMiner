package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestReorderFlagArgsSupportsFlagsAfterTargets(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "pretty", "")
	render := fs.Bool("render", true, "")
	depth := fs.Int("crawl-depth", 2, "")
	quiet := fs.Bool("quiet", false, "")

	input := []string{
		"first.js",
		"-format=json",
		"-render", "false",
		"second.js",
		"-crawl-depth", "-1",
		"-quiet",
	}
	if err := fs.Parse(reorderFlagArgs(input, fs)); err != nil {
		t.Fatal(err)
	}
	if *format != "json" || *render || *depth != -1 || !*quiet {
		t.Fatalf("flags parsed incorrectly: format=%q render=%t depth=%d quiet=%t",
			*format, *render, *depth, *quiet)
	}
	if want := []string{"first.js", "second.js"}; !reflect.DeepEqual(fs.Args(), want) {
		t.Fatalf("targets = %#v, want %#v", fs.Args(), want)
	}
}

func TestReorderFlagArgsDoesNotSwallowTargetAfterBoolean(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	render := fs.Bool("render", false, "")

	if err := fs.Parse(reorderFlagArgs([]string{"first.js", "-render", "second.js"}, fs)); err != nil {
		t.Fatal(err)
	}
	if !*render {
		t.Fatal("bare trailing boolean flag was not enabled")
	}
	if want := []string{"first.js", "second.js"}; !reflect.DeepEqual(fs.Args(), want) {
		t.Fatalf("targets = %#v, want %#v", fs.Args(), want)
	}
}
