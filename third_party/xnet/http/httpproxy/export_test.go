package httpproxy

func ExportUseProxy(cfg *Config, host string) bool {
	cfg1 := &config{
		Config: *cfg,
	}
	cfg1.init()
	return cfg1.useProxy(host)
}
