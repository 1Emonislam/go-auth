package services

import (
	"bytes"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"text/template"
	"time"
)

// EmailService handles email sending functionality
type EmailService struct {
	host     string
	port     string
	user     string
	password string
}

// Email types as constants
const (
	EmailTypeOTP   = "otp"
	EmailTypeReset = "reset"
)

// NewEmailService initializes the EmailService with SMTP credentials
func NewEmailService() *EmailService {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")

	if host == "" || port == "" || user == "" || password == "" {
		log.Fatalf("SMTP configuration is incomplete. Please set SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASS.")
	}

	log.Printf("SMTP Configuration - Host: %s, Port: %s, User: %s", host, port, user)

	return &EmailService{
		host:     host,
		port:     port,
		user:     user,
		password: password,
	}
}

// SendEmail sends an email based on the provided parameters
func (e *EmailService) SendEmail(to, subject, otp, emailType string) error {
	body, err := e.generateEmailBody(otp, time.Now().Year(), emailType)
	if err != nil {
		return fmt.Errorf("error generating email body: %w", err)
	}
	return e.sendEmail(to, subject, body)
}

// SendOTPEmail sends an OTP email to the user
func (e *EmailService) SendOTPEmail(to string, otp string) error {
	subject := "Your OTP Code"
	return e.SendEmail(to, subject, otp, EmailTypeOTP)
}

// SendResetPasswordEmail sends a reset password email to the user
func (e *EmailService) SendResetPasswordEmail(to string, otp string) error {
	subject := "Password Reset Request"
	return e.SendEmail(to, subject, otp, EmailTypeReset)
}

// sendEmail is a helper function to send an email
func (e *EmailService) sendEmail(to, subject, body string) error {
	log.Printf("Sending email to: %s", to)

	// Set up the email message
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" + body)

	log.Printf("Email message: %s", msg)

	// Check if fields are non-nil
	log.Printf("Auth fields - User: %s, Host: %s", e.user, e.host)
	auth := smtp.PlainAuth("", e.user, e.password, e.host)

	// Connect to the SMTP server
	err := smtp.SendMail(e.host+":"+e.port, auth, e.user, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
}

// generateEmailBody creates an HTML email body based on the email type
func (e *EmailService) generateEmailBody(otp string, year int, emailType string) (string, error) {
	var txtTmp string

	if emailType == EmailTypeOTP {
		txtTmp = `
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Your OTP Code</title>
			<style>
				.container {
					width: 100%;
					max-width: 600px;
					margin: auto;
					padding: 20px;
					font-family: Arial, sans-serif;
					background-color: #f7f7f7;
					border-radius: 5px;
					box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
				}
				.header {
					background-color: #007bff;
					color: white;
					padding: 10px;
					text-align: center;
					border-radius: 5px 5px 0 0;
				}
				.content {
					padding: 20px;
				}
				.footer {
					text-align: center;
					font-size: 12px;
					color: #888;
					margin-top: 20px;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h1>Your OTP Code</h1>
				</div>
				<div class="content">
					<p>Hello,</p>
					<p>Your OTP code is <strong>{{.OTP}}</strong>.</p>
					<p>This code is valid for 10 minutes.</p>
					<p>If you didn't request this code, please ignore this email.</p>
				</div>
				<div class="footer">
					<p>&copy; {{.Year}} Your Company. All rights reserved.</p>
				</div>
			</div>
		</body>
		</html>
		`
	} else if emailType == EmailTypeReset {
		txtTmp = `
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Password Reset Request</title>
			<style>
				.container {
					width: 100%;
					max-width: 600px;
					margin: auto;
					padding: 20px;
					font-family: Arial, sans-serif;
					background-color: #f7f7f7;
					border-radius: 5px;
					box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
				}
				.header {
					background-color: #dc3545;
					color: white;
					padding: 10px;
					text-align: center;
					border-radius: 5px 5px 0 0;
				}
				.content {
					padding: 20px;
				}
				.footer {
					text-align: center;
					font-size: 12px;
					color: #888;
					margin-top: 20px;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h1>Password Reset Request</h1>
				</div>
				<div class="content">
					<p>Hello,</p>
					<p>You have requested to reset your password. Your OTP code is <strong>{{.OTP}}</strong>.</p>
					<p>Please use this code to reset your password.</p>
					<p>If you didn't request this, please ignore this email.</p>
				</div>
				<div class="footer">
					<p>&copy; {{.Year}} Your Company. All rights reserved.</p>
				</div>
			</div>
		</body>
		</html>
		`
	} else {
		return "", fmt.Errorf("unknown email type: %s", emailType)
	}

	t := template.Must(template.New("emailTemplate").Parse(txtTmp))

	var body bytes.Buffer
	err := t.Execute(&body, struct {
		OTP  string
		Year int
	}{OTP: otp, Year: year})
	if err != nil {
		log.Printf("Failed to generate email body: %v", err)
		return "", fmt.Errorf("failed to generate email body: %w", err)
	}

	return body.String(), nil
}
