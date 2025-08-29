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

	"github.com/skpr/waf-notification-lambda/internal/types"
	"github.com/skpr/waf-notification-lambda/internal/waf"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// handleKeys processes multiple S3 keys, aggregating IP information from each.
func handleKeys(ctx context.Context, logger *slog.Logger, s3client *s3.Client, bucket string, keys, allowedRulesIDs []string) (map[string]types.BlockedIP, error) {
	countedIPs := make(map[string]types.BlockedIP)

	for _, key := range keys {
		ips, err := handleKey(ctx, logger, s3client, bucket, key, allowedRulesIDs)
		if err != nil {
			return nil, fmt.Errorf("failed to handle event %s: %w", key, err)
		}

		if ips == nil {
			continue
		}

		for ip, count := range ips {
			if val, exists := countedIPs[ip]; exists {
				val.Count += count
				countedIPs[ip] = val
			} else {
				countedIPs[ip] = types.BlockedIP{IP: ip, Count: 1}
			}
		}
	}

	return countedIPs, nil
}

// handleKey processes a single S3 key, downloading and parsing the WAF logs.
func handleKey(ctx context.Context, logger *slog.Logger, s3client *s3.Client, bucket, key string, allowedRulesIDs []string) (map[string]int, error) {
	logger.Info("Handling event", slog.String("uri", key))

	logger.Info("Downloading object from S3", slog.String("uri", key))

	gzipped := manager.NewWriteAtBuffer([]byte{})

	downloader, err := manager.NewDownloader(s3client).Download(ctx, gzipped, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download %s from %s: %w", key, bucket, err)
	}

	logger.Info("Finished downloading object from S3", slog.String("uri", key), slog.Int64("size", downloader))

	gzipReader, err := gzip.NewReader(bytes.NewBuffer(gzipped.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("error reading gzip: %w", err)
	}
	defer gzipReader.Close()

	ips := make(map[string]int)

	scanner := bufio.NewScanner(gzipReader)

	for scanner.Scan() {
		line := scanner.Text()

		// Nothing in this line - probably just a newline.
		if len(line) < 1 {
			continue
		}

		var log waf.Log

		if err := json.Unmarshal([]byte(line), &log); err != nil {
			logger.Error("failed to unmarshal line", "error", err.Error())
			continue
		}

		if !slices.Contains(allowedRulesIDs, log.TerminatingRuleID) {
			continue
		}

		if val, exists := ips[log.HTTPRequest.ClientIP]; exists {
			ips[log.HTTPRequest.ClientIP] = val + 1
		} else {
			ips[log.HTTPRequest.ClientIP] = 1
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return ips, nil
}
