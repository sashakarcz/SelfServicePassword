package main

import (
	"ldap-self-service/internal/config"
	"ldap-self-service/internal/handlers"
	"ldap-self-service/internal/middleware"
	"ldap-self-service/internal/services"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	ldapService := services.NewLDAPService(cfg)
	emailService := services.NewEmailService(cfg)
	smsService := services.NewSMSService(cfg)
	authService := services.NewAuthService(cfg)

	router := gin.Default()

	router.Use(middleware.CORS())
	router.Use(middleware.SessionMiddleware(cfg.SessionSecret))
	router.Use(func(c *gin.Context) {
		c.Set("authService", authService)
		c.Next()
	})

	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")

	api := router.Group("/api/v1")
	{
		api.POST("/login", handlers.Login(ldapService, authService))
		api.POST("/verify-email", handlers.VerifyEmail(emailService))
		api.POST("/verify-sms", handlers.VerifySMS(smsService))
		api.POST("/reset-password", handlers.RequestPasswordReset(ldapService, emailService, smsService))
		api.POST("/reset-password/confirm", handlers.ResetPassword(ldapService, emailService, smsService))
		
		protected := api.Group("/")
		protected.Use(middleware.AuthRequired())
		{
			protected.PUT("/password", handlers.UpdatePassword(ldapService))
			protected.GET("/ssh-keys", handlers.GetSSHKeys(ldapService))
			protected.POST("/ssh-keys", handlers.AddSSHKey(ldapService))
			protected.DELETE("/ssh-keys/:id", handlers.DeleteSSHKey(ldapService))
			protected.GET("/profile", handlers.GetProfile(ldapService))
		}
	}

	router.GET("/", handlers.Index(cfg))
	router.GET("/login", handlers.LoginPage(cfg))
	router.GET("/reset", handlers.ResetPasswordPage(cfg))
	router.GET("/dashboard", handlers.Dashboard(cfg))

	log.Printf("Server starting on port %s", cfg.Port)
	router.Run(":" + cfg.Port)
}