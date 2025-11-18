package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	"github.com/skpr/waf-notification-lambda/internal/types"
	"github.com/skpr/waf-notification-lambda/internal/waf"
)

// limit concurrency so we don't hammer S3 / exhaust Lambda CPU
const maxConcurrency = 8

// handleS3Objects processes multiple S3 keys concurrently, aggregating IP information from each.
func handleS3Objects(ctx context.Context, tracer trace.Tracer, logger *slog.Logger, s3client *s3.Client, bucket string, keys, allowedRulesIDs []string) (map[string]types.BlockedIP, error) {
	ctx, span := tracer.Start(ctx, "handleS3Objects")
	span.SetAttributes(
		attribute.String("s3.bucket", bucket),
		attribute.Int("s3.keys_count", len(keys)),
	)
	defer span.End()

	countedIPs := make(map[string]types.BlockedIP)
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)

	g.SetLimit(maxConcurrency)

	for _, key := range keys {
		key := key // capture loop variable

		g.Go(func() error {
			ips, err := handleS3Object(ctx, tracer, logger, s3client, bucket, key, allowedRulesIDs)
			if err != nil {
				return fmt.Errorf("failed to handle event %s: %w", key, err)
			}

			if ips == nil {
				return nil
			}

			// merge into shared map
			mu.Lock()
			defer mu.Unlock()

			for ip, count := range ips {
				if val, exists := countedIPs[ip]; exists {
					val.Count += count
					countedIPs[ip] = val
				} else {
					countedIPs[ip] = types.BlockedIP{
						IP:    ip,
						Count: count,
					}
				}
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	logger.Info("Finished processing S3 objects",
		slog.Int("keys", len(keys)),
		slog.Int("unique_ips", len(countedIPs)),
	)

	return countedIPs, nil
}

// handleS3Object processes a single S3 object, downloading and parsing the WAF logs.
func handleS3Object(ctx context.Context, tracer trace.Tracer, logger *slog.Logger, s3client *s3.Client, bucket, key string, allowedRuleIDs []string) (map[string]int, error) {
	ctx, span := tracer.Start(ctx, "handleS3Object")
	span.SetAttributes(
		attribute.String("s3.bucket", bucket),
		attribute.String("s3.key", key),
	)
	defer span.End()

	logger.Info("Handling event", slog.String("uri", key))
	logger.Info("Streaming object from S3", slog.String("uri", key))

	obj, err := s3client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get object from S3")
		return nil, fmt.Errorf("failed to get %s from %s: %w", key, bucket, err)
	}
	defer obj.Body.Close()

	if obj.ContentLength != nil {
		logger.Info("Got object from S3",
			slog.String("uri", key),
			slog.Int64("size", *obj.ContentLength),
		)
	}

	gzipReader, err := gzip.NewReader(obj.Body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "gzip read error")
		return nil, fmt.Errorf("error reading gzip: %w", err)
	}
	defer gzipReader.Close()

	ips := make(map[string]int)

	scanner := bufio.NewScanner(gzipReader)

	buf := make([]byte, 0, 1024*1024) // 1MB initial
	scanner.Buffer(buf, 10*1024*1024) // up to 10MB line

	_, scanSpan := tracer.Start(ctx, "scanAndParseLines")
	defer scanSpan.End()

	lineCount := 0
	matchedCount := 0

	allowedRuleSet := make(map[string]struct{}, len(allowedRuleIDs))

	for _, id := range allowedRuleIDs {
		allowedRuleSet[id] = struct{}{}
	}

	var log waf.Log

	for scanner.Scan() {
		line := scanner.Bytes()

		if len(line) == 0 {
			continue
		}
		lineCount++

		log = waf.Log{}

		if err := json.Unmarshal(line, &log); err != nil {
			logger.Error("failed to unmarshal line", "error", err.Error())
			continue
		}

		if _, ok := allowedRuleSet[log.TerminatingRuleID]; !ok {
			continue
		}

		matchedCount++
		ips[log.HTTPRequest.ClientIP]++
	}

	if err := scanner.Err(); err != nil {
		scanSpan.RecordError(err)
		scanSpan.SetStatus(codes.Error, "scanner error")
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	scanSpan.SetAttributes(
		attribute.Int("logs.total_lines", lineCount),
		attribute.Int("logs.matched_lines", matchedCount),
		attribute.Int("ips.unique_count", len(ips)),
	)

	return ips, nil
}
