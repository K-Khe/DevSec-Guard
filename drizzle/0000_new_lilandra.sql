CREATE EXTENSION IF NOT EXISTS "pgcrypto";--> statement-breakpoint
CREATE TABLE "scan_records" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"target_hostname" varchar(253) NOT NULL,
	"score" integer NOT NULL,
	"grade" varchar(2) NOT NULL,
	"detected_stack" text[] NOT NULL,
	"deterministic_findings" jsonb NOT NULL,
	"token_digest" char(64) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "scan_records_token_digest_unique" UNIQUE("token_digest"),
	CONSTRAINT "scan_records_score_range" CHECK ("scan_records"."score" between 0 and 100),
	CONSTRAINT "scan_records_grade_valid" CHECK ("scan_records"."grade" in ('A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'F')),
	CONSTRAINT "scan_records_expiry_timeline" CHECK ("scan_records"."expires_at" > "scan_records"."created_at")
);
--> statement-breakpoint
CREATE INDEX "scan_records_expires_at_idx" ON "scan_records" USING btree ("expires_at");
