-- Initial PostgreSQL setup for SecureSync.
-- Runs on first container boot (volume empty).

-- Enable UUID generation server-side (used for primary keys).
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Separate database for DefectDojo so it doesn't share tables with the platform.
SELECT 'CREATE DATABASE defectdojo'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'defectdojo')\gexec
