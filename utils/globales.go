package utils

import (
		"regexp"
		"database/sql"
)

var JWTSecret = []byte("clave-secreta-123")
var REAlfaNum = regexp.MustCompile(`^[\p{L}0-9]+$`)
var REEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
var BD *sql.DB
