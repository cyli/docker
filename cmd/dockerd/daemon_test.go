package main

import (
	"testing"

	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/internal/testutil"
	"github.com/gotestyourself/gotestyourself/assert"
	is "github.com/gotestyourself/gotestyourself/assert/cmp"
	"github.com/gotestyourself/gotestyourself/fs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

func defaultOptions(configFile string) *daemonOptions {
	opts := newDaemonOptions(&config.Config{})
	opts.flags = &pflag.FlagSet{}
	opts.InstallFlags(opts.flags)
	installConfigFlags(opts.daemonConfig, opts.flags)
	opts.flags.StringVar(&opts.configFile, "config-file", defaultDaemonConfigFile, "")
	opts.configFile = configFile
	return opts
}

func TestLoadDaemonCliConfigWithoutOverriding(t *testing.T) {
	opts := defaultOptions("")
	opts.Debug = true

	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)
	if !loadedConfig.Debug {
		t.Fatalf("expected debug to be copied from the common flags, got false")
	}
}

func TestLoadDaemonCliConfigWithTLS(t *testing.T) {
	opts := defaultOptions("")
	opts.TLSOptions.CAFile = "/tmp/ca.pem"
	opts.TLS = true

	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)
	assert.Check(t, is.Equal("/tmp/ca.pem", loadedConfig.CommonTLSOptions.CAFile))
}

func TestLoadDaemonCliConfigWithConflicts(t *testing.T) {
	tempFile := fs.NewFile(t, "config", fs.WithContent(`{"labels": ["l3=foo"]}`))
	defer tempFile.Remove()
	configFile := tempFile.Path()

	opts := defaultOptions(configFile)
	flags := opts.flags

	assert.Check(t, flags.Set("config-file", configFile))
	assert.Check(t, flags.Set("label", "l1=bar"))
	assert.Check(t, flags.Set("label", "l2=baz"))

	_, err := loadDaemonCliConfig(opts)
	testutil.ErrorContains(t, err, "as a flag and in the configuration file: labels")
}

func TestLoadDaemonCliWithConflictingNodeGenericResources(t *testing.T) {
	tempFile := fs.NewFile(t, "config", fs.WithContent(`{"node-generic-resources": ["foo=bar", "bar=baz"]}`))
	defer tempFile.Remove()
	configFile := tempFile.Path()

	opts := defaultOptions(configFile)
	flags := opts.flags

	assert.Check(t, flags.Set("config-file", configFile))
	assert.Check(t, flags.Set("node-generic-resource", "r1=bar"))
	assert.Check(t, flags.Set("node-generic-resource", "r2=baz"))

	_, err := loadDaemonCliConfig(opts)
	testutil.ErrorContains(t, err, "as a flag and in the configuration file: node-generic-resources")
}

func TestLoadDaemonCliWithConflictingLabels(t *testing.T) {
	opts := defaultOptions("")
	flags := opts.flags

	assert.Check(t, flags.Set("label", "foo=bar"))
	assert.Check(t, flags.Set("label", "foo=baz"))

	_, err := loadDaemonCliConfig(opts)
	assert.Check(t, is.Error(err, "conflict labels for foo=baz and foo=bar"))
}

func TestLoadDaemonCliWithDuplicateLabels(t *testing.T) {
	opts := defaultOptions("")
	flags := opts.flags

	assert.Check(t, flags.Set("label", "foo=the-same"))
	assert.Check(t, flags.Set("label", "foo=the-same"))

	_, err := loadDaemonCliConfig(opts)
	assert.Check(t, err)
}

func TestLoadDaemonCliWithReservedNamespaceLabels(t *testing.T) {
	for _, tc := range []struct {
		specifiedLabels []string
		expectedLabels  map[string]struct{}
	}{
		{ // all labels are propagated if there aren't any reserved namespace labels
			specifiedLabels: []string{
				"hello=world",
				"label=me",
			},
			expectedLabels: map[string]struct{}{
				"hello=world": {},
				"label=me":    {},
			},
		},
		{ // if there are no labels, no additional labels are added
			specifiedLabels: nil,
			expectedLabels:  nil,
		},
		{ // all reserved namespace labels are removed
			specifiedLabels: []string{
				"com.docker.feature=enabled",
				"io.docker.configuration=0",
				"org.dockerproject.setting=on",
			},
			expectedLabels: nil,
		},
		{ // only reserved namespaces that end with a dot are removed
			specifiedLabels: []string{
				"com.dockerpsychnotreserved.label=value",
				"COM.docker.feature=enabled",
				"io.DOCKER.CONFIGURATION=0",
				"io.dockerproject.not=reserved",
				"Org.Dockerproject.Setting=on",
				"org.docker.not=reserved",
			},
			expectedLabels: map[string]struct{}{
				"com.dockerpsychnotreserved.label=value": {},
				"io.dockerproject.not=reserved":          {},
				"org.docker.not=reserved":                {},
			},
		},
	} {
		opts := defaultOptions("")
		for _, l := range tc.specifiedLabels {
			assert.Check(t, opts.flags.Set("label", l))
		}
		conf, err := loadDaemonCliConfig(opts)
		assert.Check(t, err)
		assert.Check(t, is.Len(conf.Labels, len(tc.expectedLabels)))
		// due to stripping out the duplicate, the order of the labels are no longer guaranteed
		for _, label := range conf.Labels {
			assert.Check(t, is.Contains(tc.expectedLabels, label))
		}
	}
}

func TestLoadDaemonCliConfigWithTLSVerify(t *testing.T) {
	tempFile := fs.NewFile(t, "config", fs.WithContent(`{"tlsverify": true}`))
	defer tempFile.Remove()

	opts := defaultOptions(tempFile.Path())
	opts.TLSOptions.CAFile = "/tmp/ca.pem"

	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)
	assert.Check(t, is.Equal(loadedConfig.TLS, true))
}

func TestLoadDaemonCliConfigWithExplicitTLSVerifyFalse(t *testing.T) {
	tempFile := fs.NewFile(t, "config", fs.WithContent(`{"tlsverify": false}`))
	defer tempFile.Remove()

	opts := defaultOptions(tempFile.Path())
	opts.TLSOptions.CAFile = "/tmp/ca.pem"

	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)
	assert.Check(t, loadedConfig.TLS)
}

func TestLoadDaemonCliConfigWithoutTLSVerify(t *testing.T) {
	tempFile := fs.NewFile(t, "config", fs.WithContent(`{}`))
	defer tempFile.Remove()

	opts := defaultOptions(tempFile.Path())
	opts.TLSOptions.CAFile = "/tmp/ca.pem"

	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)
	assert.Check(t, !loadedConfig.TLS)
}

func TestLoadDaemonCliConfigWithLogLevel(t *testing.T) {
	tempFile := fs.NewFile(t, "config", fs.WithContent(`{"log-level": "warn"}`))
	defer tempFile.Remove()

	opts := defaultOptions(tempFile.Path())
	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)
	assert.Check(t, is.Equal("warn", loadedConfig.LogLevel))
	assert.Check(t, is.Equal(logrus.WarnLevel, logrus.GetLevel()))
}

func TestLoadDaemonConfigWithEmbeddedOptions(t *testing.T) {
	content := `{"tlscacert": "/etc/certs/ca.pem", "log-driver": "syslog"}`
	tempFile := fs.NewFile(t, "config", fs.WithContent(content))
	defer tempFile.Remove()

	opts := defaultOptions(tempFile.Path())
	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)
	assert.Check(t, is.Equal("/etc/certs/ca.pem", loadedConfig.CommonTLSOptions.CAFile))
	assert.Check(t, is.Equal("syslog", loadedConfig.LogConfig.Type))
}

func TestLoadDaemonConfigWithRegistryOptions(t *testing.T) {
	content := `{
		"allow-nondistributable-artifacts": ["allow-nondistributable-artifacts.com"],
		"registry-mirrors": ["https://mirrors.docker.com"],
		"insecure-registries": ["https://insecure.docker.com"]
	}`
	tempFile := fs.NewFile(t, "config", fs.WithContent(content))
	defer tempFile.Remove()

	opts := defaultOptions(tempFile.Path())
	loadedConfig, err := loadDaemonCliConfig(opts)
	assert.NilError(t, err)
	assert.Assert(t, loadedConfig != nil)

	assert.Check(t, is.Len(loadedConfig.AllowNondistributableArtifacts, 1))
	assert.Check(t, is.Len(loadedConfig.Mirrors, 1))
	assert.Check(t, is.Len(loadedConfig.InsecureRegistries, 1))
}
