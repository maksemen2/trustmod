package scorecard

type response struct {
	Score  float64 `json:"score"`
	Checks []struct {
		Name   string  `json:"name"`
		Score  float64 `json:"score"`
		Reason string  `json:"reason"`
	} `json:"checks"`
}
