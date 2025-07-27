package handlers

import (
	"ldap-self-service/internal/models"
	"ldap-self-service/internal/services"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func UpdatePassword(ldapService *services.LDAPService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.PasswordChangeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if req.NewPassword != req.ConfirmPassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
			return
		}

		userDN := c.GetString("userDN")
		if err := ldapService.UpdatePassword(userDN, req.CurrentPassword, req.NewPassword); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
	}
}

func GetProfile(ldapService *services.LDAPService) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.GetString("username")
		user, err := ldapService.GetUser(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user profile"})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

func GetSSHKeys(ldapService *services.LDAPService) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.GetString("username")
		user, err := ldapService.GetUser(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get SSH keys"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"sshKeys": user.SSHKeys})
	}
}

func AddSSHKey(ldapService *services.LDAPService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.SSHKeyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userDN := c.GetString("userDN")
		if err := ldapService.AddSSHKey(userDN, req.PublicKey); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "SSH key added successfully"})
	}
}

func DeleteSSHKey(ldapService *services.LDAPService) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyIDStr := c.Param("id")
		keyID, err := strconv.Atoi(keyIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key ID"})
			return
		}

		username := c.GetString("username")
		userDN := c.GetString("userDN")
		
		user, err := ldapService.GetUser(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
			return
		}

		if keyID < 0 || keyID >= len(user.SSHKeys) {
			c.JSON(http.StatusNotFound, gin.H{"error": "SSH key not found"})
			return
		}

		sshKey := user.SSHKeys[keyID].PublicKey
		if err := ldapService.RemoveSSHKey(userDN, sshKey); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "SSH key removed successfully"})
	}
}