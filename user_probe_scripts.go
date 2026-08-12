package main

import _ "embed"

//go:embed user-probe.sh
var userProbeShellScript string

//go:embed user-probe.ps1
var userProbePowerShellScript string
