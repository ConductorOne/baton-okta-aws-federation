package main

import (
	cfg "github.com/conductorone/baton-okta-aws-federation/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("okta-aws-federation", cfg.Config)
}
