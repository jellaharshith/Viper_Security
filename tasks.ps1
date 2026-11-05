param([Parameter(Position=0)][ValidateSet("test","lint","types","health","check")][string]$Task="check")
$py = ".\.venv\Scripts\python.exe"
switch ($Task) {
  "test"   { & $py -m pytest -q }
  "lint"   { & $py -m ruff check . }
  "types"  { & $py -m mypy src }
  "health" { & $py -m viper.cli --health }
  "check"  { & $py -m ruff check .; & $py -m mypy src; & $py -m pytest -q }
}
