package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
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
func handleS3Object(ctx context.Context, tracer trace.Tracer, logger *slog.Logger, s3client *s3.Client, bucket, key string, allowedRulesIDs []string) (map[string]int, error) {
	ctx, span := tracer.Start(ctx, "handleS3Object")
	span.SetAttributes(
		attribute.String("s3.bucket", bucket),
		attribute.String("s3.key", key),
	)
	defer span.End()

	logger.Info("Handling event", slog.String("uri", key))

	logger.Info("Downloading object from S3", slog.String("uri", key))

	gzipped := manager.NewWriteAtBuffer([]byte{})

	downloader, err := manager.NewDownloader(s3client).Download(ctx, gzipped, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to download from S3")
		return nil, fmt.Errorf("failed to download %s from %s: %w", key, bucket, err)
	}

	logger.Info("Finished downloading object from S3", slog.String("uri", key), slog.Int64("size", downloader))

	gzipReader, err := gzip.NewReader(bytes.NewBuffer(gzipped.Bytes()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "gzip read error")
		return nil, fmt.Errorf("error reading gzip: %w", err)
	}
	defer gzipReader.Close()

	ips := make(map[string]int)

	scanner := bufio.NewScanner(gzipReader)

	_, scanSpan := tracer.Start(ctx, "scanAndParseLines")
	defer scanSpan.End()

	lineCount := 0
	matchedCount := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Nothing in this line - probably just a newline.
		if len(line) < 1 {
			continue
		}

		lineCount++

		var log waf.Log

		if err := json.Unmarshal([]byte(line), &log); err != nil {
			logger.Error("failed to unmarshal line", "error", err.Error())
			continue
		}

		if !slices.Contains(allowedRulesIDs, log.TerminatingRuleID) {
			continue
		}

		matchedCount++

		if val, exists := ips[log.HTTPRequest.ClientIP]; exists {
			ips[log.HTTPRequest.ClientIP] = val + 1
		} else {
			ips[log.HTTPRequest.ClientIP] = 1
		}
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
