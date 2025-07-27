package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

func SessionMiddleware(secret string) gin.HandlerFunc {
	store := sessions.NewCookieStore([]byte(secret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   false,
		SameSite: 1,
	}

	return func(c *gin.Context) {
		session, err := store.Get(c.Request, "ldap-session")
		if err != nil {
			session, _ = store.New(c.Request, "ldap-session")
		}
		c.Set("session", session)
		c.Next()
	}
}