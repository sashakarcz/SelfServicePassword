package handlers

import (
	"ldap-self-service/internal/models"
	"ldap-self-service/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Login(ldapService *services.LDAPService, authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := ldapService.Authenticate(req.Username, req.Password)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		token, err := authService.GenerateToken(user.Username, user.DN)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token": token,
			"user":  user,
		})
	}
}

func VerifyEmail(emailService *services.EmailService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.VerificationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		valid, email := emailService.VerifyCode(req.Token, req.Code)
		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification code"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"verified": true,
			"email":    email,
		})
	}
}

func VerifySMS(smsService *services.SMSService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.VerificationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		valid, phone := smsService.VerifyCode(req.Token, req.Code)
		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification code"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"verified": true,
			"phone":    phone,
		})
	}
}