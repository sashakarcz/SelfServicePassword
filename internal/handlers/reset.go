package handlers

import (
	"ldap-self-service/internal/models"
	"ldap-self-service/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequestPasswordReset(ldapService *services.LDAPService, emailService *services.EmailService, smsService *services.SMSService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.PasswordResetRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get user from LDAP to validate username and get contact info
		user, err := ldapService.GetUser(req.Username)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		var token string
		var err2 error

		switch req.Method {
		case "email":
			if user.Email == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No email address configured for this user"})
				return
			}
			token, err2 = emailService.SendVerificationCode(user.Email)
		case "sms":
			if user.Phone == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No phone number configured for this user"})
				return
			}
			token, err2 = smsService.SendVerificationCode(user.Phone)
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reset method. Use 'email' or 'sms'"})
			return
		}

		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification code"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Verification code sent",
			"token":   token,
			"method":  req.Method,
		})
	}
}

func ResetPassword(ldapService *services.LDAPService, emailService *services.EmailService, smsService *services.SMSService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.PasswordResetConfirm
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Try to verify the code with both email and SMS services
		valid, contact := emailService.VerifyCode(req.Token, req.Code)
		if !valid {
			valid, contact = smsService.VerifyCode(req.Token, req.Code)
		}

		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired verification code"})
			return
		}

		// Find user by email or phone
		var user *models.User
		var err error
		
		// Try to find user by email first, then by phone
		if contact != "" {
			// This is a simplified approach - in a real system you'd need a more robust user lookup
			// For now, we'll require the username to be provided again in the reset flow
			c.JSON(http.StatusBadRequest, gin.H{"error": "User lookup not implemented. Please provide username"})
			return
		}

		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Reset password using admin privileges
		if err := ldapService.ResetPassword(user.DN, req.NewPassword); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
	}
}

