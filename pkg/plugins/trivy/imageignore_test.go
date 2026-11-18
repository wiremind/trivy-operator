package trivy_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestPlugin_ParseReportData_ImageIgnoreLabel(t *testing.T) {
	const label = "io.wiremind.trivy.ignore"
	ignoreFile := `vulnerabilities:
  - id: CVE-0000-0001
  - id: CVE-0000-0002
    purls:
      - pkg:deb/debian/libfoo@1.0
  - id: CVE-0000-0003
    paths:
      - usr/local/lib/app.jar
    expired_at: 2021-01-01
  - id: CVE-0000-0004
    expired_at: 2020-01-01
  - id: CVE-0000-0005
    purls:
      - pkg:deb/debian/libbar@2.0
secrets:
  - id: aws-access-key-id
`
	// Expiry is checked against the plugin's clock: CVE-0000-0003's entry is still valid then, CVE-0000-0004's is not.
	pluginClock := ext.NewFixedClock(time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC))
	all := []string{"CVE-0000-0001", "CVE-0000-0002", "CVE-0000-0003", "CVE-0000-0004", "CVE-0000-0005"}

	testCases := []struct {
		name        string
		setting     string
		labels      map[string]string
		wantVulns   []string
		wantSecrets int
	}{
		{
			name:        "hides id, purl and path entries, keeps expired and other version entries",
			setting:     label,
			labels:      map[string]string{label: gzipBase64(t, []byte(ignoreFile))},
			wantVulns:   []string{"CVE-0000-0004", "CVE-0000-0005"},
			wantSecrets: 0,
		},
		{
			name:        "setting unset",
			labels:      map[string]string{label: gzipBase64(t, []byte(ignoreFile))},
			wantVulns:   all,
			wantSecrets: 1,
		},
		{
			name:        "no label",
			setting:     label,
			wantVulns:   all,
			wantSecrets: 1,
		},
		{
			name:        "broken label",
			setting:     label,
			labels:      map[string]string{label: "not base64"},
			wantVulns:   all,
			wantSecrets: 1,
		},
		{
			name:        "file over 1 MiB",
			setting:     label,
			labels:      map[string]string{label: gzipBase64(t, append([]byte(ignoreFile+"#"), bytes.Repeat([]byte("#"), 1<<20)...))},
			wantVulns:   all,
			wantSecrets: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			labels, err := json.Marshal(tc.labels)
			require.NoError(t, err)
			input, err := writeBzip2AndEncode(fmt.Appendf(nil, `{"Metadata":{"ImageConfig":{"config":{"Labels":%s}}},"Results":[{
				"Target":"debian (debian 12.0)",
				"Vulnerabilities":[
					{"VulnerabilityID":"CVE-0000-0001","PkgName":"libfoo","InstalledVersion":"1.0"},
					{"VulnerabilityID":"CVE-0000-0002","PkgName":"libfoo","InstalledVersion":"1.0","PkgIdentifier":{"PURL":"pkg:deb/debian/libfoo@1.0"}},
					{"VulnerabilityID":"CVE-0000-0003","PkgName":"app","InstalledVersion":"1.0","PkgPath":"usr/local/lib/app.jar"},
					{"VulnerabilityID":"CVE-0000-0004","PkgName":"libfoo","InstalledVersion":"1.0"},
					{"VulnerabilityID":"CVE-0000-0005","PkgName":"libbar","InstalledVersion":"1.0","PkgIdentifier":{"PURL":"pkg:deb/debian/libbar@1.0"}}],
				"Secrets":[{"RuleID":"aws-access-key-id","Severity":"CRITICAL"}]}]}`, labels))
			require.NoError(t, err)

			config := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "trivy-operator-trivy-config", Namespace: "trivyoperator-ns"},
				Data:       map[string]string{"trivy.repository": "aquasec/trivy", "trivy.tag": "0.76.1"},
			}
			fakeClient := fake.NewClientBuilder().WithObjects(config).Build()
			ctx := trivyoperator.NewPluginContext().
				WithName("Trivy").
				WithNamespace("trivyoperator-ns").
				WithClient(fakeClient).
				WithTrivyOperatorConfig(map[string]string{
					"scanJob.compressLogs": "true",
					"imageIgnoreLabel":     tc.setting,
				}).
				Get()
			resolver := kube.NewObjectResolver(fakeClient, &kube.CompatibleObjectMapper{})
			instance := trivy.NewPlugin(pluginClock, ext.NewSimpleIDGenerator(), &resolver)

			vulnReport, secretReport, _, err := instance.ParseReportData(ctx, "alpine:3.10.2", io.NopCloser(strings.NewReader(input)))
			require.NoError(t, err)
			var gotVulns []string
			for _, v := range vulnReport.Vulnerabilities {
				gotVulns = append(gotVulns, v.VulnerabilityID)
			}
			assert.ElementsMatch(t, tc.wantVulns, gotVulns)
			assert.Len(t, secretReport.Secrets, tc.wantSecrets)
		})
	}
}

func gzipBase64(t *testing.T, data []byte) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
