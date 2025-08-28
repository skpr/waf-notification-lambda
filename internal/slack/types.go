package slack

type Document struct {
	Blocks []Block `json:"blocks,omitempty"`
}

type Block struct {
	Type string   `json:"type,omitempty"`
	Text *Text    `json:"text,omitempty"`
	Rows [][]Cell `json:"rows,omitempty"`
}

type Text struct {
	Type string `json:"type,omitempty"`
	Text string `json:"text,omitempty"`
}

type Cell struct {
	Type     string    `json:"type,omitempty"`
	Elements []Element `json:"elements,omitempty"`
}

type Element struct {
	Type     string         `json:"type,omitempty"`
	Elements []InnerElement `json:"elements,omitempty"`
}

type InnerElement struct {
	Type  string `json:"type,omitempty"`
	Text  string `json:"text,omitempty"`
	Style *Style `json:"style,omitempty"`
}

type Style struct {
	Bold bool `json:"bold,omitempty"`
}
