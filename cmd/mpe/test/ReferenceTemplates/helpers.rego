package helpers

match_any(candidates, value) {
  glob.match(candidates[_], [], value)
}
