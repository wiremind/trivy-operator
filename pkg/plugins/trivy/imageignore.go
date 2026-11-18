package trivy

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/result"
	ty "github.com/aquasecurity/trivy/pkg/types"
)

// maxImageIgnoreFileSize bounds the decompressed file, so a small label cannot fill the operator's memory.
const maxImageIgnoreFileSize = 1 << 20

var logger = ctrl.Log.WithName("plugin").WithName("trivy")

// applyImageIgnore drops from the report the vulnerabilities and secrets hidden by
// the .trivyignore.yaml stored, gzipped then base64-encoded, in the image label
// named label. Errors are logged, never returned: a returned error deletes the
// scan job and the workload is rescanned in a loop.
func (p *plugin) applyImageIgnore(report *ty.Report, label, imageRef string) {
	value := report.Metadata.ImageConfig.Config.Labels[label]
	if label == "" || value == "" {
		return
	}
	conf, err := decodeImageIgnore(clock.With(context.Background(), p.clock.Now()), value)
	if err != nil {
		logger.Error(err, "Cannot read the image ignore file, keeping the full report", "image", imageRef, "label", label)
		return
	}
	hidden := 0
	for i := range report.Results {
		r := &report.Results[i]
		before := len(r.Vulnerabilities) + len(r.Secrets)
		r.Vulnerabilities = slices.DeleteFunc(r.Vulnerabilities, func(v ty.DetectedVulnerability) bool {
			return conf.MatchVulnerability(v.VulnerabilityID, r.Target, v.PkgPath, v.PkgIdentifier.PURL) != nil
		})
		r.Secrets = slices.DeleteFunc(r.Secrets, func(s ty.DetectedSecret) bool {
			return conf.MatchSecret(s.RuleID, r.Target) != nil
		})
		hidden += before - len(r.Vulnerabilities) - len(r.Secrets)
	}
	logger.Info("Hid findings listed in the image ignore file", "image", imageRef, "hidden", hidden)
}

// decodeImageIgnore does what result.ParseIgnoreFile does for a .yaml file, from memory instead of disk.
func decodeImageIgnore(ctx context.Context, value string) (result.IgnoreConfig, error) {
	var conf result.IgnoreConfig
	zr, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(value)))
	if err != nil {
		return conf, err
	}
	data, err := io.ReadAll(io.LimitReader(zr, maxImageIgnoreFileSize+1))
	if err != nil {
		return conf, err
	}
	if len(data) > maxImageIgnoreFileSize {
		return conf, fmt.Errorf("ignore file is over %d bytes", maxImageIgnoreFileSize)
	}
	if err = yaml.Unmarshal(data, &conf); err != nil {
		return conf, err
	}
	conf.Vulnerabilities.Prune(ctx)
	conf.Secrets.Prune(ctx)
	return conf, nil
}
