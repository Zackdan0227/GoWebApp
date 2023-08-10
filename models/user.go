package models

type User struct {
	ID            int    `json:"id"`
	Email         string `json:"email"`
	Password      []byte `json:"password"`
	Is_chirpy_red bool   `json:"is_chirpy_red"`
}
