package sqs

import (
	"encoding/json"
	"fmt"
)

// ParseBody of a SQS message and marshal.
func ParseBody(body string) ([]Record, error) {
	var event Event

	err := json.Unmarshal([]byte(body), &event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %w", err)
	}

	return event.Records, nil
}
