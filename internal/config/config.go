package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Port          string `mapstructure:"port"`
	SessionSecret string `mapstructure:"session_secret"`
	SiteName      string `mapstructure:"site_name"`
	
	LDAP           LDAPConfig           `mapstructure:"ldap"`
	Email          EmailConfig          `mapstructure:"email"`
	SMS            SMSConfig            `mapstructure:"sms"`
	JWT            JWTConfig            `mapstructure:"jwt"`
	PasswordPolicy PasswordPolicyConfig `mapstructure:"password_policy"`
}

type LDAPConfig struct {
	Host           string `mapstructure:"host"`
	Port           int    `mapstructure:"port"`
	UseTLS         bool   `mapstructure:"use_tls"`
	BaseDN         string `mapstructure:"base_dn"`
	BindDN         string `mapstructure:"bind_dn"`
	BindPassword   string `mapstructure:"bind_password"`
	UserFilter     string `mapstructure:"user_filter"`
	UserBaseDN     string `mapstructure:"user_base_dn"`
	SSHKeyAttr     string `mapstructure:"ssh_key_attr"`
	EmailAttr      string `mapstructure:"email_attr"`
	PhoneAttr      string `mapstructure:"phone_attr"`
}

type EmailConfig struct {
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUser     string `mapstructure:"smtp_user"`
	SMTPPassword string `mapstructure:"smtp_password"`
	FromEmail    string `mapstructure:"from_email"`
	FromName     string `mapstructure:"from_name"`
}

type SMSConfig struct {
	Provider  string `mapstructure:"provider"`
	APIKey    string `mapstructure:"api_key"`
	APISecret string `mapstructure:"api_secret"`
	FromPhone string `mapstructure:"from_phone"`
}

type JWTConfig struct {
	Secret     string `mapstructure:"secret"`
	Expiration int    `mapstructure:"expiration"`
}

type PasswordPolicyConfig struct {
	MinLength          int    `mapstructure:"min_length"`
	MaxLength          int    `mapstructure:"max_length"`
	MinLower           int    `mapstructure:"min_lower"`
	MinUpper           int    `mapstructure:"min_upper"`
	MinDigit           int    `mapstructure:"min_digit"`
	MinSpecial         int    `mapstructure:"min_special"`
	SpecialChars       string `mapstructure:"special_chars"`
	NoReuse            bool   `mapstructure:"no_reuse"`
	DiffLogin          bool   `mapstructure:"diff_login"`
	Complexity         int    `mapstructure:"complexity"`
	UsePwnedPasswords  bool   `mapstructure:"use_pwned_passwords"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/ldap-self-service/")
	viper.AddConfigPath("$HOME/.ldap-self-service")

	viper.SetDefault("port", "8080")
	viper.SetDefault("session_secret", "change-me-in-production")
	viper.SetDefault("site_name", "LDAP Self-Service Portal")
	viper.SetDefault("ldap.port", 389)
	viper.SetDefault("ldap.use_tls", false)
	viper.SetDefault("ldap.user_filter", "(uid=%s)")
	viper.SetDefault("ldap.ssh_key_attr", "sshPublicKey")
	viper.SetDefault("ldap.email_attr", "mail")
	viper.SetDefault("ldap.phone_attr", "mobile")
	viper.SetDefault("email.smtp_port", 587)
	viper.SetDefault("jwt.expiration", 3600)
	viper.SetDefault("password_policy.min_length", 8)
	viper.SetDefault("password_policy.max_length", 128)
	viper.SetDefault("password_policy.complexity", 3)

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error
		} else {
			return nil, err
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}