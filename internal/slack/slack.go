package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/skpr/waf-notification-lambda/internal/types"
)

func PostMessage(title, description string, ips []types.BlockedIP, webhooks []string) error {
	doc := Document{
		Blocks: []Block{
			{
				Type: "header",
				Text: &Text{
					Type: "plain_text",
					Text: title,
				},
			},
			{
				Type: "section",
				Text: &Text{
					Type: "mrkdwn",
					Text: description,
				},
			},
			{
				Type: "table",
				Rows: [][]Cell{},
			},
		},
	}

	// Add a header row
	header := []Cell{
		newTextCell("IP", true),
		newTextCell("Country", true),
		newTextCell("Region", true),
		newTextCell("City", true),
		newTextCell("Org", true),
		newTextCell("Count", true),
	}
	doc.Blocks[2].Rows = append(doc.Blocks[2].Rows, header)

	for _, ip := range ips {
		row := []Cell{
			newTextCell(ip.IP, false),
			newTextCell(ip.Country, false),
			newTextCell(ip.Region, false),
			newTextCell(ip.City, false),
			newTextCell(ip.Org, false),
			newTextCell(fmt.Sprintf("%d", ip.Count), false),
		}
		doc.Blocks[2].Rows = append(doc.Blocks[2].Rows, row)
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	for _, webhook := range webhooks {
		if err := sendToWebhook(webhook, out); err != nil {
			return fmt.Errorf("failed to send to webhook %s: %w", webhook, err)
		}
	}

	return nil
}

// sendToWebhook sends the given content to the specified Slack webhook URL.
func sendToWebhook(webhook string, content []byte) error {
	req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewBuffer(content))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("returned status code: %d, body: %s", resp.StatusCode, buf.String())
	}

	return nil
}

// Helper to create a rich text cell
func newTextCell(text string, bold bool) Cell {
	style := &Style{Bold: bold}
	if !bold {
		style = nil
	}
	return Cell{
		Type: "rich_text",
		Elements: []Element{
			{
				Type: "rich_text_section",
				Elements: []InnerElement{
					{
						Type:  "text",
						Text:  text,
						Style: style,
					},
				},
			},
		},
	}
}
