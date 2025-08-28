package sqs

type Event struct {
	Records []Record `json:"Records"`
}

type Record struct {
	S3 S3 `json:"s3"`
}

type S3 struct {
	Object Object `json:"object"`
}

type Object struct {
	Key string `json:"key"`
}
