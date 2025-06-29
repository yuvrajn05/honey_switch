-- Database setup for security logs

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS security_logs;

-- Use the database
USE security_logs;

-- Create table for storing attack logs
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    request_uri VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    query_string TEXT,
    parameters TEXT,
    request_body TEXT,
    user_agent VARCHAR(255),
    timestamp TIMESTAMP NOT NULL,
    attack_type VARCHAR(50) NOT NULL
);

-- Create table for storing blocked IPs
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    blocked_at TIMESTAMP NOT NULL,
    reason VARCHAR(255) NOT NULL,
    UNIQUE KEY unique_ip (ip_address)
);

-- Create index for faster searches
CREATE INDEX idx_timestamp ON security_logs (timestamp);
CREATE INDEX idx_attack_type ON security_logs (attack_type);
CREATE INDEX idx_ip_address ON security_logs (ip_address);