package handlers

import (
	"ldap-self-service/internal/config"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Index(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title":     cfg.SiteName,
			"site_name": cfg.SiteName,
		})
	}
}

func LoginPage(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":     "Login - " + cfg.SiteName,
			"site_name": cfg.SiteName,
		})
	}
}

func Dashboard(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title":     "Dashboard - " + cfg.SiteName,
			"site_name": cfg.SiteName,
		})
	}
}

func ResetPasswordPage(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "reset.html", gin.H{
			"title":     "Reset Password - " + cfg.SiteName,
			"site_name": cfg.SiteName,
		})
	}
}