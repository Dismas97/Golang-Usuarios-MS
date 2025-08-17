package main

import (
	"database/sql"
	"fran/controles"
	"fran/utils"
	"os"
	"time"
	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/sirupsen/logrus"
)

var err error = nil

func main() {
		log.SetOutput(os.Stdout)
		log.SetLevel(log.DebugLevel)
		dsn := "root:root@tcp(127.0.0.1:3306)/ServicioLoginDB?charset=utf8mb4&parseTime=True&loc=Local"
		utils.BD, err = sql.Open("mysql", dsn)
		if err != nil {
				log.Fatalf("Error al abrir conexión: %v", err)
		}
		defer utils.BD.Close()

		utils.BD.SetMaxOpenConns(25)
		utils.BD.SetMaxIdleConns(25)
		utils.BD.SetConnMaxLifetime(5 * time.Minute)

		if err := utils.BD.Ping(); err != nil {
				log.Fatalf("Conexion BD: %v", err)
		}
		
		e := echo.New()
		e.Use(middleware.Logger())
				
		e.POST("/login", controles.Login)		
		e.POST("/registrar", controles.Registrar)
		e.GET("",controles.FiltroCheck)
		
		grupoP := e.Group("/p")		
		grupoP.Use(echojwt.JWT(utils.JWTSecret))
		grupoP.Use(controles.FiltroSuperAdmin)
		grupoP.GET("/usuario", controles.ListarUsuarios)
		grupoP.GET("/usuario/:id", controles.BuscarUsuario)
		grupoP.DELETE("/usuario/:id", controles.BajaUsuario)
		grupoP.POST("/usuario/:id", controles.ModificarUsuario)
		
		log.Errorf("Server: %v", e.Start(":4567"))
}
