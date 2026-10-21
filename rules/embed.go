package ruledata

import _ "embed"

// Default is the same rule file mounted by Compose.
//
//go:embed rules.json
var Default []byte
