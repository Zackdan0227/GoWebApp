package models

import "time"

type Revocation struct {
	Token     string    `json:"token"`
	RevokedAt time.Time `json:"revoked_at"`
}
