package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/ipinfo/go/v2/ipinfo"
	"go-simpler.org/env"

	skpripinfo "github.com/skpr/waf-notification-lambda/internal/ipinfo"
	"github.com/skpr/waf-notification-lambda/internal/slack"
	skprsqs "github.com/skpr/waf-notification-lambda/internal/sqs"
)

// Config holds the configuration for the application, loaded from environment variables.
type Config struct {
	Bucket      string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_BUCKET,required" usage:"Bucket to pull S3 objects from"`
	QueueURL    string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_SQS_QUEUE_URL,required" usage:"SQS Queue URL to read messages from"`
	BatchSize   int      `env:"SKPR_WAF_NOTIFICATION_LAMBDA_BATCH_SIZE" default:"100" usage:"Number of IPs to send in each Slack message"`
	Webhooks    []string `env:"SKPR_WAF_NOTIFICATION_LAMBDA_SLACK_WEBHOOKS,required" usage:"Slack webhook URLs to send messages to"`
	IPInfoToken string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_IPINFO_TOKEN,required" usage:"Token for authenticating with IPInfo.io"`
}

func main() {
	lambda.Start(handle)
}

func handle(ctx context.Context) error {
	cfg := Config{}

	if err := env.Load(&cfg, &env.Options{SliceSep: ","}); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	return run(ctx, cfg)
}

func run(ctx context.Context, cfg Config) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	c, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup client: %d", err)
	}

	var (
		s3Client  = s3.NewFromConfig(c)
		sqsClient = sqs.NewFromConfig(c)
	)

	var keys []string

	// Loop all the messages and extract the keys we need and extract the logs from.
	for {
		// Receive messages (max 10 at a time)
		output, err := sqsClient.ReceiveMessage(context.TODO(), &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(cfg.QueueURL),
			MaxNumberOfMessages: 10,
			WaitTimeSeconds:     5,
		})
		if err != nil {
			log.Fatalf("failed to receive message, %v", err)
		}

		// If no messages, break out
		if len(output.Messages) == 0 {
			fmt.Println("No more messages in queue.")
			break
		}

		for _, msg := range output.Messages {
			records, err := skprsqs.ParseBody(*msg.Body)
			if err != nil {
				return fmt.Errorf("failed to parse message body, %v", err)
			}

			for _, record := range records {
				keys = append(keys, record.S3.Object.Key)
			}

			_, err = sqsClient.DeleteMessage(ctx, &sqs.DeleteMessageInput{
				QueueUrl:      aws.String(cfg.QueueURL),
				ReceiptHandle: msg.ReceiptHandle,
			})
			if err != nil {
				return fmt.Errorf("failed to delete message: %w", err)
			}
		}
	}

	logger.Info("Processing keys", slog.Int("count", len(keys)))

	mappedIPs, err := handleKeys(ctx, logger, s3Client, cfg.Bucket, keys)
	if err != nil {
		return fmt.Errorf("failed to handle keys: %w", err)
	}

	logger.Info("Decorating IPs", slog.Int("count", len(mappedIPs)))

	ips, err := skpripinfo.DecorateBlockedIPs(ipinfo.NewClient(nil, nil, cfg.IPInfoToken), mappedIPs)
	if err != nil {
		return fmt.Errorf("failed to decorate IPs: %w", err)
	}

	for i := 0; i < len(ips); i += cfg.BatchSize {
		end := i + cfg.BatchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[i:end]

		err = slack.PostMessage(batch, cfg.Webhooks)
		if err != nil {
			return fmt.Errorf("failed to post to slack: %w", err)
		}
	}

	logger.Info("Finished processing keys", slog.Int("unique_ips", len(ips)))

	return nil
}
