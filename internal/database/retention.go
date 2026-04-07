// Package database provides data retention and archival management
package database

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// RetentionPolicy defines how long to keep data and where to archive it
type RetentionPolicy struct {
	ID               string              `yaml:"id" json:"id"`
	Name             string              `yaml:"name" json:"name"`
	Enabled          bool                `yaml:"enabled" json:"enabled"`
	Honeypots        []string            `yaml:"honeypots,omitempty" json:"honeypots,omitempty"`
	HotRetention     time.Duration       `yaml:"hot_retention" json:"hot_retention"`
	WarmRetention    time.Duration       `yaml:"warm_retention" json:"warm_retention"`
	ColdRetention    time.Duration       `yaml:"cold_retention" json:"cold_retention"`
	ArchiveConfig    *ArchiveConfig      `yaml:"archive,omitempty" json:"archive,omitempty"`
	CompressionType  string              `yaml:"compression" json:"compression"`
	Schedule         string              `yaml:"schedule" json:"schedule"`
	LastRun          *time.Time          `yaml:"last_run,omitempty" json:"last_run,omitempty"`
	NextRun          *time.Time          `yaml:"next_run,omitempty" json:"next_run,omitempty"`
	TotalArchived    int64               `yaml:"total_archived" json:"total_archived"`
	TotalDeleted     int64               `yaml:"total_deleted" json:"total_deleted"`
}

// ArchiveConfig defines cold storage archive settings
type ArchiveConfig struct {
	Type        string            `yaml:"type" json:"type"`           // s3, gcs, azure, filesystem
	S3          *S3Config         `yaml:"s3,omitempty" json:"s3,omitempty"`
	Filesystem  *FilesystemConfig `yaml:"filesystem,omitempty" json:"filesystem,omitempty"`
}

// S3Config defines S3-compatible storage settings
type S3Config struct {
	Endpoint        string            `yaml:"endpoint" json:"endpoint"`
	Region          string            `yaml:"region" json:"region"`
	Bucket          string            `yaml:"bucket" json:"bucket"`
	Prefix          string            `yaml:"prefix" json:"prefix"`
	AccessKeyID     string            `yaml:"access_key_id" json:"access_key_id"`
	SecretAccessKey string            `yaml:"secret_access_key" json:"secret_access_key"`
	SessionToken    string            `yaml:"session_token,omitempty" json:"session_token,omitempty"`
	PathStyle       bool              `yaml:"path_style" json:"path_style"`
	EncryptionKeyID string            `yaml:"encryption_key_id,omitempty" json:"encryption_key_id,omitempty"`
	Metadata        map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// FilesystemConfig defines local filesystem archive settings
type FilesystemConfig struct {
	Path string `yaml:"path" json:"path"`
}

// RetentionManager handles data retention and archival
type RetentionManager struct {
	policies   map[string]*RetentionPolicy
	db         Database
	s3Clients  map[string]*s3.Client
	archiveDir string
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager(db Database, archiveDir string) *RetentionManager {
	return &RetentionManager{
		policies:   make(map[string]*RetentionPolicy),
		db:         db,
		s3Clients:  make(map[string]*s3.Client),
		archiveDir: archiveDir,
	}
}

// RegisterPolicy adds a retention policy
func (rm *RetentionManager) RegisterPolicy(policy *RetentionPolicy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if policy.HotRetention == 0 {
		return fmt.Errorf("hot retention period is required")
	}

	// Set defaults
	if policy.CompressionType == "" {
		policy.CompressionType = "gzip"
	}
	if policy.Schedule == "" {
		policy.Schedule = "0 2 * * *" // Daily at 2 AM
	}

	rm.policies[policy.ID] = policy

	// Initialize S3 client if needed
	if policy.ArchiveConfig != nil && policy.ArchiveConfig.Type == "s3" {
		if err := rm.initS3Client(policy.ID, policy.ArchiveConfig.S3); err != nil {
			return fmt.Errorf("failed to initialize S3 client: %w", err)
		}
	}

	return nil
}

// initS3Client initializes an S3 client for a policy
func (rm *RetentionManager) initS3Client(policyID string, cfg *S3Config) error {
	if cfg == nil {
		return fmt.Errorf("S3 config is nil")
	}

	var optFns []func(*config.LoadOptions) error

	// Set region
	if cfg.Region != "" {
		optFns = append(optFns, config.WithRegion(cfg.Region))
	}

	// Set credentials
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		creds := credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretAccessKey,
			cfg.SessionToken,
		)
		optFns = append(optFns, config.WithCredentialsProvider(creds))
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(), optFns...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = cfg.PathStyle
		}
	})

	rm.s3Clients[policyID] = s3Client
	return nil
}

// ExecutePolicy runs a retention policy
func (rm *RetentionManager) ExecutePolicy(ctx context.Context, policyID string) (*RetentionResult, error) {
	policy, ok := rm.policies[policyID]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	if !policy.Enabled {
		return nil, fmt.Errorf("policy is disabled: %s", policyID)
	}

	slog.Info("Executing retention policy", "policy", policyID, "name", policy.Name)

	result := &RetentionResult{
		PolicyID:    policyID,
		StartedAt:   time.Now(),
		HotDeleted:  0,
		WarmDeleted: 0,
		Archived:    0,
	}

	// Calculate cutoff times
	hotCutoff := time.Now().Add(-policy.HotRetention)
	warmCutoff := time.Now().Add(-policy.WarmRetention)
	coldCutoff := time.Now().Add(-policy.ColdRetention)

	// Archive cold data before deletion
	if policy.ArchiveConfig != nil && policy.ColdRetention > 0 {
		archived, err := rm.archiveData(ctx, policy, coldCutoff, warmCutoff)
		if err != nil {
			slog.Error("Failed to archive data", "error", err)
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.Archived = archived
			policy.TotalArchived += archived
		}
	}

	// Delete expired hot data
	deleted, err := rm.deleteExpiredData(ctx, policy, hotCutoff)
	if err != nil {
		slog.Error("Failed to delete expired data", "error", err)
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.HotDeleted = deleted
		policy.TotalDeleted += deleted
	}

	// Update policy stats
	now := time.Now()
	policy.LastRun = &now
	nextRun := rm.calculateNextRun(policy.Schedule, now)
	policy.NextRun = &nextRun

	result.CompletedAt = time.Now()
	slog.Info("Retention policy completed", 
		"policy", policyID, 
		"archived", result.Archived,
		"deleted", result.HotDeleted,
		"duration", result.CompletedAt.Sub(result.StartedAt))

	return result, nil
}

// archiveData archives data to cold storage
func (rm *RetentionManager) archiveData(ctx context.Context, policy *RetentionPolicy, coldCutoff, warmCutoff time.Time) (int64, error) {
	if policy.ArchiveConfig == nil {
		return 0, nil
	}

	slog.Info("Archiving data", 
		"policy", policy.ID, 
		"from", coldCutoff, 
		"to", warmCutoff,
		"type", policy.ArchiveConfig.Type)

	switch policy.ArchiveConfig.Type {
	case "s3":
		return rm.archiveToS3(ctx, policy, coldCutoff, warmCutoff)
	case "filesystem":
		return rm.archiveToFilesystem(ctx, policy, coldCutoff, warmCutoff)
	default:
		return 0, fmt.Errorf("unsupported archive type: %s", policy.ArchiveConfig.Type)
	}
}

// archiveToS3 archives data to S3-compatible storage
func (rm *RetentionManager) archiveToS3(ctx context.Context, policy *RetentionPolicy, coldCutoff, warmCutoff time.Time) (int64, error) {
	s3Client, ok := rm.s3Clients[policy.ID]
	if !ok {
		return 0, fmt.Errorf("S3 client not initialized")
	}

	cfg := policy.ArchiveConfig.S3
	if cfg == nil {
		return 0, fmt.Errorf("S3 config is nil")
	}

	// Create archive file
	archiveFile := fmt.Sprintf("qpot_archive_%s_%s.parquet", 
		policy.ID, 
		coldCutoff.Format("20060102_150405"))
	localPath := filepath.Join(rm.archiveDir, archiveFile)

	// Export data to file (this would use the database's export functionality)
	// For now, create a placeholder
	if err := rm.exportDataToFile(ctx, policy, coldCutoff, warmCutoff, localPath); err != nil {
		return 0, fmt.Errorf("failed to export data: %w", err)
	}

	// Upload to S3
	key := filepath.Join(cfg.Prefix, archiveFile)
	if key == "." || key == "/" {
		key = archiveFile
	}

	file, err := os.Open(localPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open archive file: %w", err)
	}
	defer file.Close()

	putInput := &s3.PutObjectInput{
		Bucket: aws.String(cfg.Bucket),
		Key:    aws.String(key),
		Body:   file,
		Metadata: cfg.Metadata,
	}

	if cfg.EncryptionKeyID != "" {
		putInput.ServerSideEncryption = "aws:kms"
		putInput.SSEKMSKeyId = aws.String(cfg.EncryptionKeyID)
	}

	_, err = s3Client.PutObject(ctx, putInput)
	if err != nil {
		return 0, fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Clean up local file
	os.Remove(localPath)

	slog.Info("Archived to S3", "bucket", cfg.Bucket, "key", key)
	return 1, nil // Return count of archived batches
}

// archiveToFilesystem archives data to local filesystem
func (rm *RetentionManager) archiveToFilesystem(ctx context.Context, policy *RetentionPolicy, coldCutoff, warmCutoff time.Time) (int64, error) {
	cfg := policy.ArchiveConfig.Filesystem
	if cfg == nil {
		return 0, fmt.Errorf("filesystem config is nil")
	}

	// Ensure archive directory exists
	archivePath := filepath.Join(cfg.Path, policy.ID)
	if err := os.MkdirAll(archivePath, 0750); err != nil {
		return 0, fmt.Errorf("failed to create archive directory: %w", err)
	}

	archiveFile := fmt.Sprintf("qpot_archive_%s.parquet", 
		coldCutoff.Format("20060102_150405"))
	fullPath := filepath.Join(archivePath, archiveFile)

	if err := rm.exportDataToFile(ctx, policy, coldCutoff, warmCutoff, fullPath); err != nil {
		return 0, fmt.Errorf("failed to export data: %w", err)
	}

	slog.Info("Archived to filesystem", "path", fullPath)
	return 1, nil
}

// exportDataToFile exports data to a file
func (rm *RetentionManager) exportDataToFile(ctx context.Context, policy *RetentionPolicy, start, end time.Time, path string) error {
	// This would export data from the database in Parquet or CSV format
	// For now, create an empty file as placeholder
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header/metadata
	metadata := fmt.Sprintf("# QPot Archive\n# Policy: %s\n# Range: %s to %s\n# Honeypots: %v\n",
		policy.Name, start.Format(time.RFC3339), end.Format(time.RFC3339), policy.Honeypots)
	_, err = f.WriteString(metadata)
	return err
}

// deleteExpiredData removes data older than the retention period
func (rm *RetentionManager) deleteExpiredData(ctx context.Context, policy *RetentionPolicy, cutoff time.Time) (int64, error) {
	slog.Info("Deleting expired data", "policy", policy.ID, "cutoff", cutoff)

	// Call database-specific retention cleanup
	if err := rm.db.RetentionCleanup(ctx, cutoff); err != nil {
		return 0, fmt.Errorf("retention cleanup failed: %w", err)
	}

	return 0, nil // Actual count would come from the database
}

// ListPolicies returns all registered policies
func (rm *RetentionManager) ListPolicies() []*RetentionPolicy {
	policies := make([]*RetentionPolicy, 0, len(rm.policies))
	for _, p := range rm.policies {
		policies = append(policies, p)
	}
	return policies
}

// GetPolicy returns a specific policy
func (rm *RetentionManager) GetPolicy(id string) (*RetentionPolicy, bool) {
	p, ok := rm.policies[id]
	return p, ok
}

// DeletePolicy removes a policy
func (rm *RetentionManager) DeletePolicy(id string) {
	delete(rm.policies, id)
	delete(rm.s3Clients, id)
}

// RunScheduledChecks runs all policies that are due
func (rm *RetentionManager) RunScheduledChecks(ctx context.Context) ([]*RetentionResult, error) {
	var results []*RetentionResult

	for _, policy := range rm.policies {
		if !policy.Enabled {
			continue
		}

		if policy.NextRun == nil || time.Now().After(*policy.NextRun) {
			result, err := rm.ExecutePolicy(ctx, policy.ID)
			if err != nil {
				slog.Error("Failed to execute policy", "policy", policy.ID, "error", err)
				continue
			}
			results = append(results, result)
		}
	}

	return results, nil
}

// calculateNextRun calculates the next run time based on cron schedule
func (rm *RetentionManager) calculateNextRun(schedule string, from time.Time) time.Time {
	// Simplified: add 24 hours for daily schedules
	// In production, use a proper cron parser
	return from.Add(24 * time.Hour)
}

// RestoreFromArchive restores data from archive
func (rm *RetentionManager) RestoreFromArchive(ctx context.Context, policyID string, archiveKey string, destTable string) error {
	policy, ok := rm.policies[policyID]
	if !ok {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	if policy.ArchiveConfig == nil || policy.ArchiveConfig.Type != "s3" {
		return fmt.Errorf("S3 archive not configured")
	}

	s3Client := rm.s3Clients[policyID]
	cfg := policy.ArchiveConfig.S3

	// Download from S3
	getInput := &s3.GetObjectInput{
		Bucket: aws.String(cfg.Bucket),
		Key:    aws.String(archiveKey),
	}

	result, err := s3Client.GetObject(ctx, getInput)
	if err != nil {
		return fmt.Errorf("failed to download from S3: %w", err)
	}
	defer result.Body.Close()

	// Save to temp file
	tempFile := filepath.Join(rm.archiveDir, "restore_"+filepath.Base(archiveKey))
	f, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	_, err = io.Copy(f, result.Body)
	f.Close()
	if err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Import data (would call database-specific import)
	slog.Info("Restored from archive", "archive", archiveKey, "temp", tempFile)

	// Clean up
	os.Remove(tempFile)

	return nil
}

// RetentionResult represents the result of a retention policy execution
type RetentionResult struct {
	PolicyID    string    `json:"policy_id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Archived    int64     `json:"archived"`
	HotDeleted  int64     `json:"hot_deleted"`
	WarmDeleted int64     `json:"warm_deleted"`
	Errors      []string  `json:"errors,omitempty"`
}

// DefaultRetentionPolicy returns a default retention policy
func DefaultRetentionPolicy() *RetentionPolicy {
	return &RetentionPolicy{
		ID:              "default",
		Name:            "Default 90-Day Retention",
		Enabled:         true,
		HotRetention:    90 * 24 * time.Hour,
		WarmRetention:   180 * 24 * time.Hour,
		ColdRetention:   365 * 24 * time.Hour,
		CompressionType: "gzip",
		Schedule:        "0 2 * * *",
	}
}
