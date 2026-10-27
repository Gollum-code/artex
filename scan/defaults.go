package scan

// DefaultProfiles are the scanners ARTEX knows how to parse out of the box.
//
// enabled reflects whether the binary is expected to be present in the standard
// runtime image; ffuf ships disabled because it also needs a wordlist the operator
// must choose. A missing binary is surfaced per-profile at runtime rather than
// hiding the row, so the UI can tell the operator exactly what to install.
func DefaultProfiles() []Profile {
	return []Profile{
		{
			Name: "nuclei", Binary: "nuclei", Format: FormatNuclei,
			Args:           []string{"-u", "{{target}}", "-jsonl", "-silent", "-nc", "-duc"},
			TimeoutSeconds: 900, Enabled: true, Builtin: true,
		},
		{
			Name: "httpx", Binary: "httpx", Format: FormatHttpx,
			Args:           []string{"-u", "{{target}}", "-json", "-silent", "-nc", "-status-code", "-title", "-tech-detect", "-favicon"},
			TimeoutSeconds: 600, Enabled: true, Builtin: true,
		},
		{
			Name: "subfinder", Binary: "subfinder", Format: FormatSubfinder,
			Args:           []string{"-d", "{{target}}", "-json", "-silent"},
			TimeoutSeconds: 600, Enabled: true, Builtin: true,
		},
		{
			Name: "katana", Binary: "katana", Format: FormatKatana,
			Args:           []string{"-u", "{{target}}", "-jsonl", "-silent", "-nc"},
			TimeoutSeconds: 900, Enabled: true, Builtin: true,
		},
		{
			Name: "ffuf", Binary: "ffuf", Format: FormatFfuf,
			Args:           []string{"-u", "{{target}}", "-w", "{{wordlist}}", "-of", "json", "-o", "{{outfile}}", "-s"},
			TimeoutSeconds: 900, Enabled: false, Builtin: true,
		},
	}
}
