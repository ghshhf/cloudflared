// Command swbn-pkg bundles a compiled sidecar binary + the cloudflared
// executable + manifest.json into a single .swbn archive.
//
//   Usage:  swbn-pkg --sidecar ./sidecar --cloudflared ./cloudflared --manifest ./manifest.json --out cloudflared.swbn
//
// The archive layout (standardised by the SkyNet SSI spec):
//
//   manifest.json         -> top-level component metadata
//   sidecar               -> our Go wrapper (executable)
//   bin/cloudflared       -> upstream cloudflared binary (executable)
//
// SkyNet's runtime unzips the .swbn to a temporary directory, then spawns
// `./sidecar` and drives it over stdin/stdout JSON-RPC.
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	sidecarPath := flag.String("sidecar", "", "path to the compiled cloudflared-sidecar binary")
	cloudflaredPath := flag.String("cloudflared", "", "path to the upstream cloudflared binary")
	manifestPath := flag.String("manifest", "manifest.json", "path to the component manifest.json")
	outPath := flag.String("out", "cloudflared.swbn", "output .swbn file path")
	flag.Parse()

	if err := pack(*sidecarPath, *cloudflaredPath, *manifestPath, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, "pack failed:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", *outPath)
}

func pack(sidecar, cloudflared, manifest, out string) error {
	if sidecar == "" || cloudflared == "" {
		return fmt.Errorf("--sidecar and --cloudflared are required")
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	// manifest.json goes in unmodified.
	if err := addFile(zw, "manifest.json", manifest); err != nil {
		return err
	}
	if err := addFile(zw, "sidecar", sidecar); err != nil {
		return err
	}
	if err := addFile(zw, filepath.Join("bin", "cloudflared"), cloudflared); err != nil {
		return err
	}

	// Attach a small README for people who unzip the archive by hand so they
	// know what they are looking at.
	readme := fmt.Sprintf("cloudflared-sidecar 0.1.0 (built for %s/%s)\n\nThis archive was produced by swbn-pkg. Load it into the SkyNet runtime to\nmanage Cloudflare tunnels through the SSI lifecycle interface.\n", runtime.GOOS, runtime.GOARCH)
	if err := addString(zw, "README.txt", readme); err != nil {
		return err
	}
	return nil
}

func addFile(zw *zip.Writer, name, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	hdr, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	hdr.Name = name
	// Mark executables on Unix platforms; harmless on Windows.
	if strings.Contains(name, "sidecar") || strings.Contains(name, "cloudflared") {
		hdr.SetMode(0o755)
	}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}

func addString(zw *zip.Writer, name, content string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(content))
	return err
}
