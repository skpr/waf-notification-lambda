package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"slices"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/ipinfo/go/v2/ipinfo"
	"go-simpler.org/env"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	skpripinfo "github.com/skpr/waf-notification-lambda/internal/ipinfo"
	"github.com/skpr/waf-notification-lambda/internal/slack"
	skprsqs "github.com/skpr/waf-notification-lambda/internal/sqs"
	"github.com/skpr/waf-notification-lambda/internal/types"
)

// Config holds the configuration for the application, loaded from environment variables.
type Config struct {
	ServiceName             string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_SERVICE_NAME" usage:"Name of the service for logging and telemetry"`
	Bucket                  string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_BUCKET,required" usage:"Bucket to pull S3 objects from"`
	QueueURL                string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_SQS_QUEUE_URL,required" usage:"SQS Queue URL to read messages from"`
	BatchSize               int      `env:"SKPR_WAF_NOTIFICATION_LAMBDA_BATCH_SIZE" default:"100" usage:"Number of IPs to send in each Slack message"`
	Webhooks                []string `env:"SKPR_WAF_NOTIFICATION_LAMBDA_SLACK_WEBHOOKS,required" usage:"Slack webhook URLs to send messages to"`
	IPInfoToken             string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_IPINFO_TOKEN,required" usage:"Token for authenticating with IPInfo.io"`
	AllowedRulesIDs         []string `env:"SKPR_WAF_NOTIFICATION_LAMBDA_ALLOWED_RULES_IDS,required" usage:"Comma-separated list of allowed WAF rule IDs"`
	SlackMessageTitle       string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_SLACK_MESSAGE_TITLE" default:"WAF Blocked IPs" usage:"Title for the Slack message"`
	SlackMessageDescription string   `env:"SKPR_WAF_NOTIFICATION_LAMBDA_SLACK_MESSAGE_DESCRIPTION" default:"The following IPs have been blocked by the WAF:" usage:"Description for the Slack message"`
}

func main() {
	ctx := context.Background()

	tp, err := xrayconfig.NewTracerProvider(ctx)
	if err != nil {
		fmt.Printf("error creating tracer provider: %v", err)
	}

	defer func(ctx context.Context) {
		err := tp.Shutdown(ctx)
		if err != nil {
			fmt.Printf("error shutting down tracer provider: %v", err)
		}
	}(ctx)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(xray.Propagator{})

	lambda.Start(otellambda.InstrumentHandler(handle(ctx), xrayconfig.WithRecommendedOptions(tp)...))
}

func handle(ctx context.Context) error {
	cfg := Config{}

	if err := env.Load(&cfg, &env.Options{SliceSep: ","}); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	tracer := otel.Tracer(cfg.ServiceName)
	ctx, span := tracer.Start(ctx, "handle")
	defer span.End()

	return run(ctx, tracer, logger, cfg)
}

func run(ctx context.Context, tracer trace.Tracer, logger *slog.Logger, cfg Config) error {
	ctx, span := tracer.Start(ctx, "run")
	defer span.End()

	c, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup client: %d", err)
	}

	var (
		s3Client  = s3.NewFromConfig(c)
		sqsClient = sqs.NewFromConfig(c)
	)

	var keys []string

	_, receiveMessagesSpan := tracer.Start(ctx, "receiveMessage")

	// Loop all the messages and extract the keys we need and extract the logs from.
	for {
		// Receive messages (max 10 at a time)
		output, err := sqsClient.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(cfg.QueueURL),
			MaxNumberOfMessages: 10,
			// We don't want to long poll. Leave it for the next execution.
			WaitTimeSeconds: 0,
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

	receiveMessagesSpan.End()

	logger.Info("Processing keys", slog.Int("count", len(keys)))

	mappedIPs, err := handleS3Objects(ctx, tracer, logger, s3Client, cfg.Bucket, keys, cfg.AllowedRulesIDs)
	if err != nil {
		return fmt.Errorf("failed to handle keys: %w", err)
	}

	logger.Info("Decorating IPs", slog.Int("count", len(mappedIPs)))

	ctx, decorateSpan := tracer.Start(ctx, "decorateBlockedIPs")

	ips, err := skpripinfo.DecorateBlockedIPs(ipinfo.NewClient(nil, nil, cfg.IPInfoToken), mappedIPs)
	if err != nil {
		return fmt.Errorf("failed to decorate IPs: %w", err)
	}

	decorateSpan.End()

	logger.Info("Sorting IPs", slog.Int("count", len(ips)))

	slices.SortFunc(ips, func(a, b types.BlockedIP) int {
		return b.Count - a.Count
	})

	logger.Info("Sending messages to Slack", slog.Int("unique_ips", len(ips)), slog.Int("batch_size", cfg.BatchSize))

	ctx, slackSpan := tracer.Start(ctx, "sendToSlack")

	for i := 0; i < len(ips); i += cfg.BatchSize {
		end := i + cfg.BatchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[i:end]

		err = slack.PostMessage(cfg.SlackMessageTitle, cfg.SlackMessageDescription, batch, cfg.Webhooks)
		if err != nil {
			return fmt.Errorf("failed to post to slack: %w", err)
		}
	}

	slackSpan.End()

	logger.Info("Finished processing keys", slog.Int("unique_ips", len(ips)))

	return nil
}
